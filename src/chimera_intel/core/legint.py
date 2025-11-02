"""
Module for Legal Intelligence (LEGINT).

Handles the gathering of intelligence from legal sources, such as court dockets,
case filings, sanctions lists, and corporate registries.
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
    PIIFinding
)
from .utils import save_or_print_results
from .database import save_scan_to_db, get_scan_from_db, update_scan_in_db
from .config_loader import API_KEYS
from .http_client import sync_client
from .project_manager import resolve_target

logger = logging.getLogger(__name__)

# --- PII Redaction Engine ---

# More comprehensive regex patterns
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

    Args:
        data (Dict[str, Any]): The raw data collected from a module.
        module_name (str): The name of the module that collected the data.
        frameworks (List[str]): List of frameworks (e.g., "GDPR", "CCPA").

    Returns:
        A tuple containing:
        - ComplianceCheckResult: A report on the PII found.
        - Dict[str, Any]: The data dictionary, modified in-place with redactions.
    """
    logger.info(f"Running compliance check on data from '{module_name}'...")
    result = ComplianceCheckResult(
        module=module_name, regulatory_frameworks=frameworks
    )
    result.total_items_scanned = 1  # We scan the whole blob as one item

    # The 'data' dict is modified IN-PLACE
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


# --- CourtListener ---

def search_court_dockets(company_name: str) -> DocketSearchResult:
    """
    Searches for court dockets related to a company name using the CourtListener API.

    Args:
        company_name (str): The name of the company to search for in court records.

    Returns:
        DocketSearchResult: A Pydantic model with the search results.
    """
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


# --- OpenSanctions ---

def screen_for_sanctions(entity_name: str) -> SanctionsScreeningResult:
    """
    Screens an entity name against international sanctions lists using the
    free OpenSanctions API.

    Args:
        entity_name (str): The name of the company, person, or entity to screen.

    Returns:
        SanctionsScreeningResult: A Pydantic model with the screening results.
    """
    logger.info(f"Screening '{entity_name}' against OpenSanctions lists...")
    
    base_url = "https://api.opensanctions.org/search"
    # Note: OpenSanctions free API doesn't require a key, but is rate-limited.
    # A commercial provider would require an API key in headers.
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
            
            # Use score to filter out low-confidence matches
            if res.get("score", 0) < 60: # Heuristic threshold
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


# --- OpenCorporates ---

def get_ubo_data(company_name: str) -> UboResult:
    """
    Retrieves corporate records and officers (as a proxy for UBOs)
    using the OpenCorporates API. This is a 2-step process.

    Args:
        company_name (str): The name of the company.

    Returns:
        UboResult: A Pydantic model with UBO data.
    """
    logger.info(f"Retrieving corporate data for '{company_name}'...")
    api_key = API_KEYS.opencorporates_api_key
    if not api_key:
        return UboResult(
            company_name=company_name,
            error="OpenCorporates API key (opencorporates_api_key) not found in .env file.",
        )

    # --- Step 1: Search for the company to get its unique identifier ---
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

        # Take the top search result
        top_company = companies[0]["company"]
        company_jurisdiction = top_company.get("jurisdiction_code")
        company_number = top_company.get("company_number")
        resolved_company_name = top_company.get("name")
        
        logger.info(f"Found company: {resolved_company_name}. Fetching full record...")

        # --- Step 2: Fetch the full company record using its identifier ---
        # This endpoint provides officer data, which is our best proxy for UBOs
        # on most OpenCorporates plans.
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

            # This is a proxy. A true PEP check would involve screening the name.
            is_pep = any(kw in officer.get("position", "").lower() for kw in ["political", "government", "minister"])

            ubos.append(UboData(
                name=officer_name,
                ownership_percentage=0.0, # This data is rarely available
                is_pep=is_pep,
                details=f"Position: {officer.get('position', 'N/A')}",
                nationality=officer.get("nationality"),
                address=officer.get("address", {}).get("full_address")
            ))

        return UboResult(
            company_name=resolved_company_name,
            ultimate_beneficial_owners=ubos,
            corporate_structure=record_data # Store the full record for context
        )

    except Exception as e:
        logger.error(f"Failed to get UBO data for {company_name}: {e}")
        return UboResult(
            company_name=company_name, error=f"An API error occurred: {e}"
        )


# --- Typer CLI Application ---

legint_app = typer.Typer()

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
    """Searches court records for dockets related to a company."""
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
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Screens an entity and (optionally) its UBOs against sanctions lists."""
    try:
        target_entity = resolve_target(entity_name, required_assets=["company_name"])
        all_results = {}
        
        # 1. Screen the primary entity
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
                # We also add the PEP status from the UBO data to the screening result
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

        save_or_print_results(all_results, output_file)
        save_scan_to_db(
            target=target_entity, module="legint_sanctions_screener", data=all_results
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
    Filters a stored scan result for PII and compliance issues.
    By default, this command is non-destructive and only generates a report.
    Use --redact to permanently modify the stored scan.
    """
    try:
        scan = get_scan_from_db(scan_id)
        if not scan:
            typer.echo(f"Error: Scan with ID {scan_id} not found.", err=True)
            raise typer.Exit(code=1)
        
        typer.echo(f"Checking scan {scan_id} (Module: {scan.module}) for compliance...")
        scan_data = json.loads(scan.result)
        
        # Run the filtering logic
        # This function modifies scan_data IN-PLACE
        check_results, modified_data = filter_pii_data(scan_data, scan.module, frameworks)
        
        results_dict = check_results.model_dump(exclude_none=True, by_alias=True)
        
        if redact_in_place:
            if check_results.total_findings > 0:
                typer.echo(f"[DANGER] Redacting {check_results.total_findings} items and overwriting scan {scan_id} in database...")
                update_scan_in_db(scan_id, json.dumps(modified_data))
                typer.echo("[SUCCESS] Scan has been permanently redacted.")
                # Save the *report* to the file
                save_or_print_results(results_dict, output_file)
            else:
                typer.echo("No PII found. No redaction necessary.")
                save_or_print_results(results_dict, output_file)
        else:
            # Default: Just save/print the compliance report
            typer.echo("Run with --redact to save changes to the database.")
            save_or_print_results(results_dict, output_file)
        
        if check_results.total_findings > 0:
            typer.echo(f"[WARNING] Found {check_results.total_findings} potential PII issues.", err=True)
        else:
            typer.echo("[SUCCESS] No PII issues found.")

    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)