"""
Module for Legal Intelligence (LEGINT).

Handles the gathering of intelligence from legal sources, such as court dockets,
case filings, sanctions lists, corporate registries, and regulatory filings.
"""

import typer
import logging
import re
import json
from typing import Optional, List, Dict, Any
from .schemas import (
    DocketSearchResult,
    CourtRecord,
    SanctionsScreeningResult,
    SanctionedEntity,
    UboResult,
    UboData,
    ComplianceCheckResult,
    PIIFinding,
    ArbitrationFinding,
    ArbitrationSearchResult,
    ExportControlResult,
    ExportControlFinding,
    LobbyingSearchResult,
    LobbyingActivity
)
from .utils import save_or_print_results
from .database import ( # <-- MODIFIED
    save_scan_to_db, 
    get_scan_from_db, 
    update_scan_in_db,
    get_db_connection
)
from .config_loader import API_KEYS
from .http_client import sync_client
from .project_manager import resolve_target, list_projects, get_project_config_by_name # <-- ADDED
from .google_search import search_google 
from .alert_manager import alert_manager_instance, AlertLevel # <-- ADDED
from .scheduler import add_job # <-- ADDED

logger = logging.getLogger(__name__)




# --- PII Redaction Engine ---

PII_PATTERNS = {
    "Email": r"[\w\.-]+@[\w\.-]+\.\w+",
    "Phone (US)": r"\(?\b\d{3}\)?[\s\.-]?\d{3}[\s\.-]?\d{4}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    # IPv4 can be sensitive, e.g., in internal logs
    "IPv4 Address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", 
}

def _redact_string(text: str, result_object: ComplianceCheckResult, field_name: str) -> str:
    """Helper function to find and redact PII in a single string."""
    if not isinstance(text, str):
        return text

    for pii_type, pattern in PII_PATTERNS.items():
        try:
            # We use re.sub with a function to capture what was found
            def replacer(match):
                found_text = match.group(0)
                # Create a redacted snippet for the log
                if len(found_text) > 7:
                    snippet = f"{found_text[:2]}...{found_text[-4:]}"
                else:
                    snippet = "[REDACTED]"
                
                result_object.findings.append(
                    PIIFinding(
                        data_field=field_name,
                        pii_type=pii_type,
                        data_snippet=snippet,
                        status="Redacted"
                    )
                )
                return f"[REDACTED_{pii_type.upper()}]"

            text = re.sub(pattern, replacer, text)
        except Exception as e:
            logger.warning(f"Error during PII regex for {pii_type}: {e}")
            
    return text

def _traverse_and_redact(node: Any, result_object: ComplianceCheckResult, current_path="root"):
    """Recursively traverse the data structure to find and redact strings."""
    if isinstance(node, dict):
        # Iterate over a copy of keys to allow modification
        for key, value in list(node.items()):
            new_path = f"{current_path}.{key}"
            if isinstance(value, str):
                node[key] = _redact_string(value, result_object, field_name=new_path)
            else:
                _traverse_and_redact(value, result_object, current_path=new_path)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            new_path = f"{current_path}[{i}]"
            if isinstance(item, str):
                node[i] = _redact_string(item, result_object, field_name=new_path)
            else:
                _traverse_and_redact(item, result_object, current_path=new_path)

def filter_pii_data(
    data: Dict[str, Any], module_name: str, frameworks: List[str]
) -> tuple[ComplianceCheckResult, Dict[str, Any]]:
    """
    A real-time filtering engine to flag and redact PII from collected data
    using a comprehensive set of regex patterns.
    """
    logger.info(f"Running compliance check on data from '{module_name}'...")
    result = ComplianceCheckResult(
        module=module_name, regulatory_frameworks=frameworks
    )
    result.total_items_scanned = 1  # We scan the whole blob as one item

    _traverse_and_redact(data, result)
    
    result.total_findings = len(result.findings)
    if result.total_findings > 0:
        logger.warning(
            f"Redacted {result.total_findings} PII findings from '{module_name}' data."
        )
        result.message = f"Compliance check complete. Redacted {result.total_findings} PII items."
    else:
        logger.info("No PII found in compliance check.")
        result.message = "Compliance check complete. No PII found."
        
    return result, data # Return both the report and the modified data


# --- CourtListener (Existing) ---
# This covers "Litigation & Legal Risk" (Court Cases)

def search_court_dockets(company_name: str) -> DocketSearchResult:
    """
    Searches for court dockets related to a company name using the CourtListener API.
    """
    # ... (existing function code) ...
    api_key = API_KEYS.courtlistener_api_key
    if not api_key:
        return DocketSearchResult(
            query=company_name,
            error="CourtListener API key not found in .env file.",
        )
    logger.info(f"Searching CourtListener for dockets related to: {company_name}")

    base_url = "https://www.courtlistener.com/api/rest/v3/search/"
    headers = {"Authorization": f"Token {api_key}"}
    params = {
        "q": company_name,
        "type": "d", # d = dockets
        "order_by": "dateFiled desc",
    }  

    try:
        response = sync_client.get(base_url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        records = [CourtRecord.model_validate(rec) for rec in data.get("results", [])]

        return DocketSearchResult(
            query=company_name,
            total_found=data.get("count", 0),
            records=records,
        )
    except Exception as e:
        logger.error(f"Failed to get court dockets for {company_name}: {e}")
        return DocketSearchResult(
            query=company_name, error=f"An API error occurred: {e}"
        )

# --- NEW: Arbitration & Disputes Search ---
# This expands "Litigation & Legal Risk" (Disputes, Arbitration)

def search_arbitration_records(entity_name: str) -> ArbitrationSearchResult:
    """
    Searches for public records of arbitration and major legal disputes
    using a general web search.
    """
    logger.info(f"Searching for arbitration/disputes involving: {entity_name}")
    query = f'"{entity_name}" AND (arbitration OR "legal dispute" OR lawsuit OR settlement)'
    
    try:
        # Assumes search_google returns List[Dict[str, str]]
        # with keys 'title', 'url', 'snippet'
        search_results = search_google(query, num_results=10)
        
        findings = []
        for res in search_results:
            title = res.get("title", "No Title")
            url = res.get("url")
            snippet = res.get("snippet", "No Snippet")
            
            case_type = "Arbitration" if "arbitration" in snippet.lower() else "Dispute/Litigation"
            
            findings.append(ArbitrationFinding(
                case_title=title,
                source_url=url,
                snippet=snippet,
                case_type=case_type
            ))

        return ArbitrationSearchResult(query=entity_name, findings=findings)
        
    except Exception as e:
        logger.error(f"Failed to search for arbitration data for {entity_name}: {e}")
        return ArbitrationSearchResult(
            query=entity_name, error=f"An API error occurred: {e}"
        )


# --- OpenSanctions (Existing) ---
# This covers "Sanctions & Export Controls" (Sanctions)

def screen_for_sanctions(entity_name: str) -> SanctionsScreeningResult:
    """
    Screens an entity name against international sanctions lists using the
    free OpenSanctions API.
    """
    # ... (existing function code) ...
    logger.info(f"Screening '{entity_name}' against OpenSanctions lists...")
    
    base_url = "https://api.opensanctions.org/search"
    params = {
        "q": entity_name,
        "limit": 10
    }

    try:
        response = sync_client.get(base_url, params=params)
        response.raise_for_status()
        data = response.json()
        
        results = data.get("results", [])
        if not results:
            return SanctionsScreeningResult(query=entity_name, hits_found=0, entities=[])

        hits = []
        for res in results:
            props = res.get("properties", {})
            programs = props.get("program", [])
            addresses = props.get("address", [])
            
            if res.get("score", 0) < 60:
                continue

            hit = SanctionedEntity(
                name=res.get("caption", "Unknown Name"),
                address=addresses[0] if addresses else "N/A",
                type=res.get("schema", "Unknown"),
                programs=programs,
                score=int(res.get("score", 0))
            )
            hits.append(hit)

        return SanctionsScreeningResult(
            query=entity_name,
            hits_found=len(hits),
            entities=hits
        )
    except Exception as e:
        logger.error(f"Failed to screen sanctions for {entity_name}: {e}")
        return SanctionsScreeningResult(
            query=entity_name, error=f"An API error occurred: {e}"
        )

# --- NEW: Export Controls Check ---
# This expands "Sanctions & Export Controls" (Trade Restrictions, Embargoes)

def check_export_controls(entity_name: str, country_code: str = "US") -> ExportControlResult:
    """
    Checks for entity inclusion in export control lists (e.g., US Consolidated
    Screening List) using a general web search.
    """
    logger.info(f"Checking export controls for: {entity_name} (Country: {country_code})")
    
    # This query targets the official US CSL search tool and other .gov sites
    query = (
        f'"{entity_name}" site:gov '
        f'(("Consolidated Screening List" OR "Entity List" OR OFAC OR ITAR OR EAR))'
    )
    
    try:
        search_results = search_google(query, num_results=5)
        
        findings = []
        for res in search_results:
            snippet = res.get("snippet", "")
            
            # Simple keyword matching for list names
            source_list = "Unknown"
            if "Consolidated Screening List" in snippet or "trade.gov" in res.get("url"):
                source_list = "US Consolidated Screening List"
            elif "OFAC" in snippet:
                source_list = "OFAC"
            elif "Entity List" in snippet or "bis.doc.gov" in res.get("url"):
                source_list = "BIS Entity List"
                
            findings.append(ExportControlFinding(
                entity_name=entity_name,
                source_list=source_list,
                source_url=res.get("url"),
                details=snippet
            ))

        return ExportControlResult(query=entity_name, findings=findings)
        
    except Exception as e:
        logger.error(f"Failed to check export controls for {entity_name}: {e}")
        return ExportControlResult(
            query=entity_name, error=f"An API error occurred: {e}"
        )


# --- NEW: Lobbying & Political Influence ---

def search_lobbying_data(entity_name: str) -> LobbyingSearchResult:
    """
    Searches for lobbying expenditures and political donations using a
    general web search targeting sites like OpenSecrets.
    """
    logger.info(f"Searching for lobbying/political influence data for: {entity_name}")
    
    # Query targets common data sources
    queries = [
        f'"{entity_name}" lobbying expenditures site:opensecrets.org',
        f'"{entity_name}" political donations site:fec.gov'
    ]
    
    try:
        all_activities = []
        for query in queries:
            search_results = search_google(query, num_results=3)
            for res in search_results:
                # This is a heuristic. A real implementation would need
                # a dedicated scraper or API for OpenSecrets/FEC.
                # We'll use the snippet to find money.
                snippet = res.get("snippet", "")
                amount_match = re.search(r"\$([\d,]+)", snippet)
                
                if amount_match:
                    amount = float(amount_match.group(1).replace(",", ""))
                    all_activities.append(LobbyingActivity(
                        payee="Unknown (from search snippet)",
                        amount=amount,
                        date="Unknown",
                        source_url=res.get("url"),
                        purpose=snippet
                    ))

        return LobbyingSearchResult(query=entity_name, activities=all_activities)
        
    except Exception as e:
        logger.error(f"Failed to search for lobbying data for {entity_name}: {e}")
        return LobbyingSearchResult(
            query=entity_name, error=f"An API error occurred: {e}"
        )


# --- OpenCorporates (Existing) ---

def get_ubo_data(company_name: str) -> UboResult:
    """
    Retrieves corporate records and officers (as a proxy for UBOs)
    using the OpenCorporates API. This is a 2-step process.
    """
    # ... (existing function code) ...
    logger.info(f"Retrieving corporate data for '{company_name}'...")
    api_key = API_KEYS.opencorporates_api_key
    if not api_key:
        return UboResult(
            company_name=company_name,
            error="OpenCorporates API key (opencorporates_api_key) not found in .env file.",
        )

    search_url = "https://api.opencorporates.com/v0.4/companies/search"
    search_params = {
        "q": company_name,
        "api_token": api_key,
        "order": "score"
    }

    try:
        response = sync_client.get(search_url, params=search_params)
        response.raise_for_status()
        data = response.json()

        companies = data.get("results", {}).get("companies", [])
        if not companies:
            return UboResult(company_name=company_name, ultimate_beneficial_owners=[], error="Company not found.")

        top_company = companies[0]["company"]
        company_jurisdiction = top_company.get("jurisdiction_code")
        company_number = top_company.get("company_number")
        resolved_company_name = top_company.get("name")
        
        logger.info(f"Found company: {resolved_company_name}. Fetching full record...")

        record_url = f"https://api.opencorporates.com/v0.4/companies/{company_jurisdiction}/{company_number}"
        record_params = {
            "api_token": api_key
        }
        
        record_response = sync_client.get(record_url, params=record_params)
        record_response.raise_for_status()
        record_data = record_response.json().get("results", {}).get("company", {})

        officers = record_data.get("officers", [])
        if not officers:
            return UboResult(
                company_name=resolved_company_name,
                ultimate_beneficial_owners=[],
                corporate_structure=record_data,
                error="Company found, but no officers listed."
            )

        ubos = []
        for item in officers:
            officer = item.get("officer", {})
            officer_name = officer.get('name')
            if not officer_name:
                continue

            is_pep = any(kw in officer.get("position", "").lower() for kw in ["political", "government", "minister"])

            ubos.append(UboData(
                name=officer_name,
                ownership_percentage=0.0,
                is_pep=is_pep,
                details=f"Position: {officer.get('position', 'N/A')}",
                nationality=officer.get("nationality"),
                address=officer.get("address", {}).get("full_address")
            ))

        return UboResult(
            company_name=resolved_company_name,
            ultimate_beneficial_owners=ubos,
            corporate_structure=record_data
        )

    except Exception as e:
        logger.error(f"Failed to get UBO data for {company_name}: {e}")
        return UboResult(
            company_name=company_name, error=f"An API error occurred: {e}"
        )


# --- NEW: Legal Activity Monitoring ---

def _analyze_docket_role(case_name: str, entity_name: str) -> Optional[str]:
    """
    Analyzes a court case name to determine the role of the entity (Plaintiff or Defendant).
    """
    entity_name_lower = entity_name.lower()
    case_name_lower = case_name.lower()

    # Regex to find "v." or "versus" with entity as defendant
    # Needs word boundaries to avoid matching "EvilCorp" in "EvilCorpTest"
    if re.search(rf"(v\.|versus)\s+\b{re.escape(entity_name_lower)}\b", case_name_lower):
        return "Defendant"
    
    # Regex to find entity as plaintiff
    if re.search(rf"\b{re.escape(entity_name_lower)}\b\s+(v\.|versus)", case_name_lower):
        return "Plaintiff"
    
    # Fallback if name is just in the case
    if entity_name_lower in case_name_lower:
        return "Party (Role Unclear)"
    
    return None

def monitor_legal_activity(project_name: str):
    """
    Daemon-callable function to monitor legal activity for a single project's
    competitors and key personnel.
    """
    logger.info(f"Running legal activity monitor for project: {project_name}")
    
    config = get_project_config_by_name(project_name)
    if not config:
        logger.error(f"Could not load project config for '{project_name}'. Skipping.")
        return

    # 1. Build dictionary of targets to monitor
    targets_to_monitor: Dict[str, str] = {} # { "entity_name": "entity_type" }
    for comp in config.competitors:
        targets_to_monitor[comp] = "Competitor"
    for person in config.key_personnel:
        targets_to_monitor[person] = "Key Personnel"

    if not targets_to_monitor:
        logger.info(f"No competitors or key personnel to monitor for '{project_name}'.")
        return

    # 2. Get docket numbers from the last successful run
    seen_dockets = set()
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Find the most recent 'legint_monitor' scan for this project
            cursor.execute(
                """
                SELECT result FROM scan_results
                WHERE project_name = %s AND module = %s
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (project_name, "legint_monitor")
            )
            record = cursor.fetchone()
            if record:
                last_run_data = json.loads(record[0])
                seen_dockets = set(last_run_data.get("all_found_dockets", []))
                logger.info(f"Loaded {len(seen_dockets)} seen dockets from last run.")
                
    except Exception as e:
        logger.error(f"Failed to get last scan results from DB for '{project_name}': {e}")
    finally:
        if conn:
            conn.close()

    # 3. Loop through targets, search for dockets, and dispatch alerts
    new_dockets_found = []
    all_dockets_this_run = []
    
    for entity_name, entity_type in targets_to_monitor.items():
        logger.debug(f"Searching dockets for {entity_type}: {entity_name}")
        docket_result = search_court_dockets(entity_name)
        
        if docket_result.error or not docket_result.records:
            continue
            
        for record in docket_result.records:
            all_dockets_this_run.append(record.docket_number)
            
            # This is the core logic: check if it's new
            if record.docket_number not in seen_dockets:
                role = _analyze_docket_role(record.case_name, entity_name)
                if not role:
                    continue # Ignore if the name match is ambiguous

                logger.warning(
                    f"New legal docket found for {entity_type} '{entity_name}': {record.case_name}"
                )
                
                # Dispatch an alert
                alert_title = f"New Legal Activity: {entity_type}"
                alert_message = (
                    f"New lawsuit found for {entity_type} '{entity_name}'.\n"
                    f"Role: {role}\n"
                    f"Case: {record.case_name}\n"
                    f"Court: {record.court}\n"
                    f"URL: {record.docket_url}"
                )
                alert_manager_instance.dispatch_alert(
                    title=alert_title,
                    message=alert_message,
                    level=AlertLevel.WARNING,
                    provenance={"module": "legint_monitor", "project": project_name, "target": entity_name}
                )
                new_dockets_found.append(record.model_dump(by_alias=True))

    # 4. Save this run's results to the database for next time
    if new_dockets_found:
        logger.info(f"Found {len(new_dockets_found)} total new dockets for '{project_name}'.")
        report = {
            "new_findings": new_dockets_found,
            "all_found_dockets": list(set(all_dockets_this_run)) # Deduplicate
        }
        save_scan_to_db(
            target=project_name, 
            module="legint_monitor", 
            data=report
        )
    else:
        logger.info(f"No new legal activity found for project: {project_name}")


def run_all_project_legal_monitors():
    """
    Wrapper function for the scheduler.
    Iterates through all projects and runs the legal monitor for each.
    """
    logger.info("DAEMON: Starting scheduled run for legal activity monitor...")
    try:
        project_names = list_projects()
        if not project_names:
            logger.info("DAEMON: No projects found to monitor.")
            return

        logger.info(f"DAEMON: Found {len(project_names)} projects to monitor.")
        for project_name in project_names:
            try:
                monitor_legal_activity(project_name)
            except Exception as e:
                logger.error(
                    f"DAEMON: Unhandled error while monitoring project '{project_name}': {e}",
                    exc_info=True
                )
        logger.info("DAEMON: Finished scheduled run for legal activity monitor.")
    except Exception as e:
        logger.error(
            f"DAEMON: Critical error during job startup (e.g., DB connection): {e}",
            exc_info=True
        )

# --- Typer CLI Application ---

legint_app = typer.Typer(help="Legal Intelligence (LEGINT) tools for compliance, sanctions, and litigation.")

@legint_app.command("docket-search")
def run_docket_search(
    company_name: Optional[str] = typer.Option(
        None,
        "--company-name",
        "-n",
        help="The company name to search. Uses active project if not provided.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """(Existing) Searches court records for dockets related to a company."""
    try:
        target_company = resolve_target(company_name, required_assets=["company_name"])

        results_model = search_court_dockets(target_company)
        if results_model.error:
            typer.echo(f"Error: {results_model.error}", err=True)
            raise typer.Exit(code=1)
        results_dict = results_model.model_dump(exclude_none=True, by_alias=True)
        save_or_print_results(results_dict, output_file)
        save_scan_to_db(
            target=target_company, module="legint_docket_search", data=results_dict
        )
    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)

# --- NEW CLI COMMAND ---
@legint_app.command("arbitration-search")
def run_arbitration_search(
    entity_name: Optional[str] = typer.Option(
        None,
        "--entity-name",
        "-n",
        help="The entity to search for arbitration/disputes. Uses active project if not provided.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """(New) Searches public web for arbitration cases and legal disputes."""
    try:
        target_entity = resolve_target(entity_name, required_assets=["company_name"])

        results_model = search_arbitration_records(target_entity)
        if results_model.error:
            typer.echo(f"Error: {results_model.error}", err=True)
            raise typer.Exit(code=1)
        
        results_dict = results_model.model_dump(exclude_none=True, by_alias=True)
        save_or_print_results(results_dict, output_file)
        save_scan_to_db(
            target=target_entity, module="legint_arbitration_search", data=results_dict
        )
    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)


@legint_app.command("sanctions-screener")
def run_sanctions_screener(
    entity_name: Optional[str] = typer.Option(
        None,
        "--entity-name",
        "-n",
        help="The entity (company or person) to screen. Uses active project if not provided.",
    ),
    include_ubo: bool = typer.Option(
        False,
        "--ubo",
        help="Also attempt to find and screen Ultimate Beneficial Owners (UBOs).",
    ),
    # --- NEW OPTION ---
    include_export_controls: bool = typer.Option(
        False,
        "--export-controls",
        help="Also screen against export control lists (e.g., US Entity List).",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """(Updated) Screens entity/UBOs against sanctions and export control lists."""
    try:
        target_entity = resolve_target(entity_name, required_assets=["company_name"])
        all_results = {}
        
        # 1. Screen the primary entity (OpenSanctions)
        typer.echo(f"Screening primary entity: {target_entity}")
        sanctions_results = screen_for_sanctions(target_entity)
        all_results["primary_entity_screening"] = sanctions_results.model_dump(exclude_none=True)

        if sanctions_results.error:
            typer.echo(f"Error screening primary entity: {sanctions_results.error}", err=True)
            
        # 2. Handle UBO screening if requested
        if include_ubo:
            typer.echo(f"Attempting to find officers/UBOs for: {target_entity}")
            ubo_data = get_ubo_data(target_entity)
            all_results["ubo_data"] = ubo_data.model_dump(exclude_none=True, by_alias=True)
            
            if ubo_data.error:
                typer.echo(f"Error finding UBOs: {ubo_data.error}", err=True)
            
            ubo_screenings = []
            for ubo in ubo_data.ultimate_beneficial_owners:
                typer.echo(f"Screening officer/UBO: {ubo.name}")
                ubo_sanctions = screen_for_sanctions(ubo.name)
                if ubo.is_pep:
                    ubo_sanctions.hits_found += 1
                    ubo_sanctions.entities.append(SanctionedEntity(
                        name=ubo.name,
                        type="Person",
                        programs=["PEP (Politically Exposed Person)"],
                        score=100,
                        address=ubo.address
                    ))
                ubo_screenings.append(ubo_sanctions.model_dump(exclude_none=True))
            all_results["ubo_screenings"] = ubo_screenings

        # 3. Handle Export Controls if requested
        if include_export_controls:
            typer.echo(f"Checking export control lists for: {target_entity}")
            export_results = check_export_controls(target_entity)
            all_results["export_control_screening"] = export_results.model_dump(exclude_none=True, by_alias=True)
            if export_results.error:
                typer.echo(f"Error checking export controls: {export_results.error}", err=True)


        save_or_print_results(all_results, output_file)
        save_scan_to_db(
            target=target_entity, module="legint_sanctions_screener", data=all_results
        )

    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)

# --- NEW CLI COMMAND ---
@legint_app.command("lobbying-search")
def run_lobbying_search(
    entity_name: Optional[str] = typer.Option(
        None,
        "--entity-name",
        "-n",
        help="The entity to search for lobbying data. Uses active project if not provided.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """(New) Searches for political donations and lobbying expenditures."""
    try:
        target_entity = resolve_target(entity_name, required_assets=["company_name"])

        results_model = search_lobbying_data(target_entity)
        if results_model.error:
            typer.echo(f"Error: {results_model.error}", err=True)
            raise typer.Exit(code=1)
        
        results_dict = results_model.model_dump(exclude_none=True, by_alias=True)
        save_or_print_results(results_dict, output_file)
        save_scan_to_db(
            target=target_entity, module="legint_lobbying_search", data=results_dict
        )
    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)


@legint_app.command("compliance-check")
def run_compliance_check(
    scan_id: int = typer.Argument(
        ..., help="The ID of the scan result to check from the database."
    ),
    frameworks: List[str] = typer.Option(
        ["GDPR", "CCPA"],
        "--framework",
        "-f",
        help="Regulatory frameworks to check against.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save compliance report to a JSON file."
    ),
    redact_in_place: bool = typer.Option(
        False,
        "--redact",
        help="DANGEROUS: Redact the data and save it back to the database.",
    ),
):
    """
    (Existing) Filters a stored scan result for PII and compliance issues.
    """
    # ... (existing function code) ...
    try:
        scan = get_scan_from_db(scan_id)
        if not scan:
            typer.echo(f"Error: Scan with ID {scan_id} not found.", err=True)
            raise typer.Exit(code=1)
        
        typer.echo(f"Checking scan {scan_id} (Module: {scan.module}) for compliance...")
        scan_data = json.loads(scan.result)
        
        check_results, modified_data = filter_pii_data(scan_data, scan.module, frameworks)
        
        results_dict = check_results.model_dump(exclude_none=True, by_alias=True)
        
        if redact_in_place:
            if check_results.total_findings > 0:
                typer.echo(f"[DANGER] Redacting {check_results.total_findings} items and overwriting scan {scan_id} in database...")
                update_scan_in_db(scan_id, json.dumps(modified_data))
                typer.echo("[SUCCESS] Scan has been permanently redacted.")
                save_or_print_results(results_dict, output_file)
            else:
                typer.echo("No PII found. No redaction necessary.")
                save_or_print_results(results_dict, output_file)
        else:
            typer.echo("Run with --redact to save changes to the database.")
            save_or_print_results(results_dict, output_file)
        
        if check_results.total_findings > 0:
            typer.echo(f"[WARNING] Found {check_results.total_findings} potential PII issues.", err=True)
        else:
            typer.echo("[SUCCESS] No PII issues found.")

    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)

# --- NEW CLI COMMAND FOR SCHEDULING ---
@legint_app.command("monitor-schedule-add")
def schedule_legal_monitor(
    schedule: str = typer.Option(
        "0 9 * * 1-5", # 9 AM on Weekdays
        "--schedule",
        "-s",
        help="Cron schedule (e.g., '0 9 * * 1-5' for 9 AM on weekdays)."
    ),
):
    """(New) Schedules the legal monitor to run periodically.
    
    This job will iterate through all projects, find their defined
    competitors and key personnel, and alert on new court dockets.
    """
    try:
        job_id = "global_legal_monitor"
        add_job(
            func=run_all_project_legal_monitors,
            trigger="cron",
            cron_schedule=schedule,
            job_id=job_id,
            kwargs={},
        )
        typer.echo(
            f"[bold green]Successfully scheduled legal monitor job '{job_id}' "
            f"with schedule: '{schedule}'[/bold green]"
        )
        typer.echo("The daemon will now run this check automatically.")
    except Exception as e:
        typer.echo(f"An unexpected error occurred while scheduling: {e}", err=True)
        raise typer.Exit(code=1)