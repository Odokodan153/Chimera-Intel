"""
Module for advanced, in-depth reconnaissance to gather specific intelligence data.
"""

import typer
import logging
import asyncio
from typing import Optional, List
from google_play_scraper import search as search_google_play  # type: ignore
from .schemas import (
    CredentialExposureResult,
    CompromisedCredential,
    AssetIntelResult,
    MobileApp,
    ThreatInfraResult,
    RelatedIndicator,
)
from .utils import save_or_print_results
from .database import save_scan_to_db
from .config_loader import API_KEYS
from .http_client import sync_client, async_client

logger = logging.getLogger(__name__)


def find_credential_leaks(domain: str) -> CredentialExposureResult:
    """Searches for compromised credentials from breach data using the SpyCloud API.

    This function queries the SpyCloud API, a leading provider of recaptured breach
    data, to find credentials associated with a given domain.

    Args:
        domain (str): The domain to check for credential leaks.

    Returns:
        CredentialExposureResult: A Pydantic model with credentials found in breach data.
    """
    api_key = API_KEYS.spycloud_api_key
    if not api_key:
        return CredentialExposureResult(
            target_domain=domain, error="SpyCloud API key not found in .env file."
        )
    logger.info(f"Searching SpyCloud for credential leaks associated with: {domain}")

    base_url = "https://api.spycloud.io/enterprise-api/v1/breach/data"
    headers = {"X-Api-Key": api_key}
    params = {"domain": domain, "limit": 100}

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
            target_domain=domain, error=f"An error occurred with the SpyCloud API: {e}"
        )


async def find_digital_assets(company_name: str) -> AssetIntelResult:
    """Discovers digital assets like mobile apps and public datasets.

    This function searches for mobile applications on the Google Play Store and
    looks for public datasets associated with the company name.

    Args:
        company_name (str): The company name to find assets for.

    Returns:
        AssetIntelResult: A Pydantic model with discovered mobile apps and datasets.
    """
    logger.info(f"Discovering digital assets for company: {company_name}")

    # --- Find Mobile Apps ---

    mobile_apps: List[MobileApp] = []
    try:
        # Use google-play-scraper to find apps by the company name

        results = await asyncio.to_thread(
            lambda: search_google_play(query=company_name, n_hits=5)
        )
        for app_info in results:
            if company_name.lower() in app_info.get("developer", "").lower():
                mobile_apps.append(
                    MobileApp(
                        app_name=app_info.get("title"),
                        app_id=app_info.get("appId"),
                        store="Google Play",
                        developer=app_info.get("developer"),
                        permissions=[],  # Permissions require deeper analysis, omitted for brevity
                        embedded_endpoints=[],
                    )
                )
    except Exception as e:
        logger.error(f"Failed to scrape Google Play for '{company_name}': {e}")
    # --- Find Public Datasets (Conceptual Search) ---
    # This simulates a search on platforms like Kaggle, data.gov, etc.

    mock_datasets = [
        f"s3://{company_name.lower().replace(' ', '-')}-research-data-public"
    ]

    return AssetIntelResult(
        target_company=company_name,
        mobile_apps=mobile_apps,
        public_datasets=mock_datasets,
    )


async def analyze_threat_infrastructure(indicator: str) -> ThreatInfraResult:
    """Performs a reverse pivot on an indicator using the VirusTotal API.

    This function finds other domains and IPs that are related to the initial
    indicator, helping to map out adversary infrastructure.

    Args:
        indicator (str): A malicious IP or domain to investigate.

    Returns:
        ThreatInfraResult: A Pydantic model with related indicators.
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


# --- Typer CLI Application ---


recon_app = typer.Typer()


@recon_app.command("credentials")
def run_credential_recon(
    domain: str = typer.Argument(..., help="The domain to check for credential leaks."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Searches breach data for compromised credentials associated with a domain."""
    results = find_credential_leaks(domain)
    results_dict = results.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=domain, module="recon_credentials", data=results_dict)


@recon_app.command("assets")
def run_asset_intel(
    company_name: str = typer.Argument(
        ..., help="The company name to find assets for."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Discovers digital assets like mobile apps and public datasets."""
    results = asyncio.run(find_digital_assets(company_name))
    results_dict = results.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=company_name, module="recon_assets", data=results_dict)


@recon_app.command("threat-infra")
def run_threat_infra_recon(
    indicator: str = typer.Argument(
        ..., help="A malicious IP or domain to investigate."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Analyzes and pivots on adversary threat infrastructure."""
    results = asyncio.run(analyze_threat_infrastructure(indicator))
    results_dict = results.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=indicator, module="recon_threat_infra", data=results_dict)
