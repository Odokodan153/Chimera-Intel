import typer
import logging
import asyncio
from typing import Optional, List, Dict, Union
from datetime import datetime

from google_play_scraper import search as search_google_play  # type: ignore
from .schemas import (
    CredentialExposureResult,
    CompromisedCredential,
    AssetIntelResult,
    MobileApp,
    ThreatInfraResult,
    RelatedIndicator,
    # --- NEW SCHEMAS ADDED ---
    PassiveDNSResult,
    PassiveDNSRecord,
)
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .config_loader import API_KEYS
from .http_client import sync_client, async_client
from .project_manager import get_active_project


logger = logging.getLogger(__name__)


def find_credential_leaks(domain: str) -> CredentialExposureResult:
    """Searches for compromised credentials from breach data using the SpyCloud API.

    This function queries the SpyCloud API, a leading provider of recaptured breach
    data, to find credentials associated with a given domain.

    Args:
        domain (str): The domain to check for credential leaks.

    Returns:
        CredentialExposureResult: A Pantic model with credentials found in breach data.
    """
    api_key = API_KEYS.spycloud_api_key
    if not api_key:
        return CredentialExposureResult(
            target_domain=domain,
            total_found=0,
            error="SpyCloud API key not found in .env file.",
        )
    logger.info(f"Searching SpyCloud for credential leaks associated with: {domain}")

    base_url = "https://api.spycloud.io/enterprise-api/v1/breach/data"
    headers = {"X-Api-Key": api_key}
    params: Dict[str, Union[str, int]] = {"domain": domain, "limit": 100}

    try:
        response = sync_client.get(base_url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        credentials = [
            CompromisedCredential(
                email=result.get("email"),
                source_breach=result.get("source_id"),
                password_hash=result.get("password"),  # May be hash or plaintext
                is_plaintext="plaintext" in result.get("password_type", ""),
            )
            for result in data.get("results", [])
        ]

        return CredentialExposureResult(
            target_domain=domain,
            total_found=data.get("num_results", 0),
            compromised_credentials=credentials,
        )
    except Exception as e:
        logger.error(f"Failed to get credential leaks from SpyCloud for {domain}: {e}")
        return CredentialExposureResult(
            target_domain=domain,
            total_found=0,
            error=f"An error occurred with the SpyCloud API: {e}",
        )


async def find_digital_assets(company_name: str) -> AssetIntelResult:
    """Discovers digital assets like mobile apps and public datasets.

    This function searches for mobile applications on the Google Play Store and
    looks for public datasets associated with the company name on Kaggle.
    """
    logger.info(f"Discovering digital assets for company: {company_name}")

    # --- Find Mobile Apps ---

    mobile_apps: List[MobileApp] = []
    try:
        results = await asyncio.to_thread(
            lambda: search_google_play(query=company_name, n_hits=5)
        )

        for app_info in results:
            mobile_apps.append(
                MobileApp(
                    app_name=app_info.get("title")
                    or app_info.get("name")
                    or "Unknown App",
                    app_id=app_info.get("appId", "unknown"),
                    store="Google Play",
                    developer=app_info.get("developer", "Unknown Developer"),
                    permissions=[],
                    embedded_endpoints=[],
                )
            )
    except Exception as e:
        logger.error(f"Failed to scrape Google Play for '{company_name}': {e}")
    # --- Find Public Datasets from Kaggle ---

    public_datasets: List[str] = []

    kaggle_key = getattr(API_KEYS, "kaggle_api_key", None)
    if kaggle_key:
        try:
            import kaggle  # type: ignore[import]

            api = kaggle.KaggleApi()
            api.authenticate()
            datasets = await asyncio.to_thread(
                lambda: api.dataset_list(search=company_name)
            )

            for dataset in datasets:
                ref = getattr(dataset, "ref", None)
                if ref:
                    public_datasets.append(f"kaggle://{ref}")
        except Exception as e:
            logger.warning(
                f"Failed to search Kaggle datasets for '{company_name}': {e}"
            )
    else:
        logger.info("Kaggle API key not provided – skipping dataset search.")
    return AssetIntelResult(
        target_company=company_name,
        mobile_apps=mobile_apps,
        public_datasets=public_datasets,
    )


async def analyze_threat_infrastructure(indicator: str) -> ThreatInfraResult:
    """Performs a reverse pivot on an indicator using the VirusTotal API.

    This function finds other domains and IPs that are related to the initial
    indicator, helping to map out adversary infrastructure.

    Args:
        indicator (str): A malicious IP or domain to investigate.

    Returns:
        ThreatInfraResult: A Pantic model with related indicators.
    """
    api_key = API_KEYS.virustotal_api_key
    if not api_key:
        return ThreatInfraResult(
            initial_indicator=indicator, error="VirusTotal API key not found."
        )
    logger.info(f"Analyzing threat infrastructure related to: {indicator}")
    headers = {"x-apikey": api_key}

    # Determine if the indicator is an IP or a domain

    url_part = (
        "ip_addresses" if all(c.isdigit() or c == "." for c in indicator) else "domains"
    )

    # Use the 'relationships' endpoint for richer data

    url = f"https://www.virustotal.com/api/v3/{url_part}/{indicator}/resolutions"

    related_indicators: List[RelatedIndicator] = []

    try:
        response = await async_client.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        data = response.json().get("data", [])

        for item in data[:15]:  # Limit to 15 for brevity
            attributes = item.get("attributes", {})
            if url_part == "domains":
                related_indicators.append(
                    RelatedIndicator(
                        indicator_type="IP Address",
                        value=attributes.get("ip_address"),
                        relation="Resolved to",
                    )
                )
            else:  # ip_addresses
                related_indicators.append(
                    RelatedIndicator(
                        indicator_type="Domain",
                        value=attributes.get("host_name"),
                        relation="Hosted on same IP",
                    )
                )
    except Exception as e:
        logger.error(f"Failed to analyze threat infrastructure for '{indicator}': {e}")
        return ThreatInfraResult(
            initial_indicator=indicator,
            error=f"An error occurred with the VirusTotal API: {e}",
        )
    return ThreatInfraResult(
        initial_indicator=indicator,
        related_indicators=related_indicators,
    )


# --- NEW FUNCTION ADDED ---
async def query_passive_dns(indicator: str) -> PassiveDNSResult:
    """
    Queries the VirusTotal API for passive DNS data on an indicator.

    Args:
        indicator (str): A domain or IP address.

    Returns:
        PassiveDNSResult: A Pydantic model with historical DNS records.
    """
    api_key = API_KEYS.virustotal_api_key
    if not api_key:
        return PassiveDNSResult(
            query_indicator=indicator,
            total_records=0,
            error="VirusTotal API key not found.",
        )
    logger.info(f"Querying passive DNS for: {indicator}")
    headers = {"x-apikey": api_key}

    # Determine if the indicator is an IP or a domain
    is_ip = all(c.isdigit() or c == "." for c in indicator)
    url_part = "ip_addresses" if is_ip else "domains"

    url = f"https://www.virustotal.com/api/v3/{url_part}/{indicator}/passive_dns"
    records: List[PassiveDNSRecord] = []

    try:
        response = await async_client.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        data = response.json().get("data", [])

        for item in data:
            attributes = item.get("attributes", {})
            
            first_seen_ts = attributes.get("first_seen")
            last_seen_ts = attributes.get("last_seen")
            
            first_seen_str = datetime.utcfromtimestamp(first_seen_ts).isoformat() if first_seen_ts else "N/A"
            last_seen_str = datetime.utcfromtimestamp(last_seen_ts).isoformat() if last_seen_ts else "N/A"

            # Determine hostname and value based on query type
            hostname = attributes.get("hostname")
            value = attributes.get("ip_address") if not is_ip else indicator

            records.append(
                PassiveDNSRecord(
                    hostname=hostname,
                    record_type=attributes.get("record_type"),
                    value=value,
                    first_seen=first_seen_str,
                    last_seen=last_seen_str,
                    source=item.get("type", "passive_dns_record") # Use the item type as the source
                )
            )
        
        return PassiveDNSResult(
            query_indicator=indicator,
            total_records=len(records),
            records=records
        )
    except Exception as e:
        logger.error(f"Failed to query passive DNS for '{indicator}': {e}")
        return PassiveDNSResult(
            query_indicator=indicator,
            total_records=0,
            error=f"An error occurred with the VirusTotal API: {e}",
        )

# --- Typer CLI Application ---


recon_app = typer.Typer()


@recon_app.command("credentials")
def run_credential_recon(
    domain: Optional[str] = typer.Argument(
        None, help="The domain to check. Uses active project if not provided."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Searches breach data for compromised credentials associated with a domain."""
    target_domain = domain
    if not target_domain:
        active_project = get_active_project()
        if active_project and active_project.domain:
            target_domain = active_project.domain
            console.print(
                f"[bold cyan]Using domain '{target_domain}' from active project '{active_project.project_name}'.[/bold cyan]"
            )
        else:
            console.print(
                "[bold red]Error:[/bold red] No domain provided and no active project set."
            )
            raise typer.Exit(code=1)
    results = find_credential_leaks(target_domain)
    results_dict = results.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=target_domain, module="recon_credentials", data=results_dict)


@recon_app.command("assets")
def run_asset_intel(
    company_name: Optional[str] = typer.Argument(
        None,
        help="The company name to find assets for. Uses active project if not provided.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Discovers digital assets like mobile apps and public datasets."""
    target_company = company_name
    if not target_company:
        active_project = get_active_project()
        if active_project and active_project.company_name:
            target_company = active_project.company_name
            console.print(
                f"[bold cyan]Using company name '{target_company}' from active project '{active_project.project_name}'.[/bold cyan]"
            )
        else:
            console.print(
                "[bold red]Error:[/bold red] No company name provided and no active project with a company name is set."
            )
            raise typer.Exit(code=1)
    results = asyncio.run(find_digital_assets(target_company))
    results_dict = results.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=target_company, module="recon_assets", data=results_dict)


@recon_app.command("threat-infra")
def run_threat_infra_recon(
    indicator: Optional[str] = typer.Argument(
        None,
        help="A malicious IP or domain. Uses active project's domain if not provided.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Analyzes and pivots on adversary threat infrastructure."""
    target_indicator = indicator
    if not target_indicator:
        active_project = get_active_project()
        if active_project and active_project.domain:
            target_indicator = active_project.domain
            console.print(
                f"[bold cyan]Using indicator '{target_indicator}' from active project '{active_project.project_name}'.[/bold cyan]"
            )
        else:
            console.print(
                "[bold red]Error:[/bold red] No indicator provided and no active project set."
            )
            raise typer.Exit(code=1)
    results = asyncio.run(analyze_threat_infrastructure(target_indicator))
    results_dict = results.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_indicator, module="recon_threat_infra", data=results_dict
    )

# --- NEW CLI COMMAND ADDED ---
@recon_app.command("passive-dns-query")
def run_passive_dns_query(
    indicator: str = typer.Argument(..., help="The domain or IP to query in pDNS databases."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Queries Passive DNS databases for historical infrastructure connections."""
    logger.info("Starting Passive DNS query for: '%s'", indicator)
    results = asyncio.run(query_passive_dns(indicator))
    results_dict = results.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=indicator, module="recon_passive_dns", data=results_dict
    )