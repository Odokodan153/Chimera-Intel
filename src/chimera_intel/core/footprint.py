import typer
import whois  # type: ignore
import dns.resolver
import asyncio
import re
import shodan  # type: ignore
from rich.panel import Panel
from dotenv import load_dotenv
from typing import Dict, Any, List, Optional
import logging
from httpx import RequestError, HTTPStatusError
from chimera_intel.core.utils import console, save_or_print_results, is_valid_domain
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.config_loader import CONFIG, API_KEYS
from chimera_intel.core.schemas import (
    FootprintResult,
    FootprintData,
    SubdomainReport,
    ScoredResult,
)
from chimera_intel.core.http_client import async_client

# Import the new threat intel function


from .threat_intel import get_threat_intel_otx

logger = logging.getLogger(__name__)
load_dotenv()

# --- Synchronous Helper Functions ---


def get_whois_info(domain: str) -> Dict[str, Any]:
    """
    Retrieves WHOIS information for a given domain.

    Args:
        domain (str): The domain to perform the WHOIS lookup on.

    Returns:
        Dict[str, Any]: A dictionary of the WHOIS record, or an error message.
    """
    try:
        domain_info = whois.whois(domain)
        if domain_info and domain_info.get("domain_name"):
            return dict(domain_info)
        else:
            return {"error": "No WHOIS record found."}
    except Exception as e:
        logger.error(
            "An exception occurred during WHOIS lookup for '%s': %s", domain, e
        )
        return {"error": f"An exception occurred during WHOIS lookup: {e}"}


def get_dns_records(domain: str) -> Dict[str, Any]:
    """
    Retrieves common DNS records for a given domain, configured via config.yaml.

    Args:
        domain (str): The domain to query for DNS records.

    Returns:
        Dict[str, Any]: A dictionary where keys are record types (e.g., 'A', 'MX') and
                        values are lists of records, or an error message.
    """
    dns_results: Dict[str, Any] = {}
    record_types = CONFIG.modules.footprint.dns_records_to_query
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            dns_results[record_type] = [str(r.to_text()).strip('"') for r in answers]
        except dns.resolver.NoAnswer:
            dns_results[record_type] = None
        except dns.resolver.NXDOMAIN:
            logger.warning("DNS query failed for '%s' (NXDOMAIN).", domain)
            return {"error": f"Domain does not exist (NXDOMAIN): {domain}"}
        except Exception as e:
            logger.error(
                "Could not resolve DNS record type '%s' for '%s': %s",
                record_type,
                domain,
                e,
            )
            dns_results[record_type] = [f"Could not resolve {record_type}: {e}"]
    return dns_results


# --- Asynchronous Data Gathering Functions ---


async def get_subdomains_virustotal(domain: str, api_key: str) -> List[str]:
    """
    Asynchronously retrieves subdomains from the VirusTotal API.

    Args:
        domain (str): The domain to query for subdomains.
        api_key (str): The VirusTotal API key.

    Returns:
        List[str]: A list of subdomain strings found.
    """
    if not api_key:
        return []
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100"
    try:
        response = await async_client.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return [item.get("id") for item in data.get("data", [])]
    except (HTTPStatusError, RequestError) as e:
        logger.error(
            "Error fetching subdomains from VirusTotal for '%s': %s", domain, e
        )
        return []


async def get_subdomains_dnsdumpster(domain: str) -> List[str]:
    """
    Asynchronously scrapes subdomains from DNSDumpster by handling CSRF tokens.

    Args:
        domain (str): The domain to query for subdomains.

    Returns:
        List[str]: A list of subdomain strings found.
    """
    try:
        home_response = await async_client.get("https://dnsdumpster.com/")
        home_response.raise_for_status()
        csrf_token = home_response.cookies.get("csrftoken")
        if not csrf_token:
            logger.warning("Could not retrieve CSRF token from DNSDumpster.")
            return []
        post_data = {
            "csrfmiddlewaretoken": csrf_token,
            "targetip": domain,
            "user": "free",
        }
        headers = {"Referer": "https://dnsdumpster.com/"}
        results_response = await async_client.post(
            "https://dnsdumpster.com/", data=post_data, headers=headers
        )
        results_response.raise_for_status()
        subdomains = re.findall(
            r'<td class="col-md-4">([\w\d\.\-]+\.' + re.escape(domain) + r")<br>",
            results_response.text,
        )
        return list(set(subdomains))
    except (HTTPStatusError, RequestError) as e:
        logger.error("Error scraping DNSDumpster for '%s': %s", domain, e)
        return []


async def get_subdomains_threatminer(domain: str) -> List[str]:
    """
    Asynchronously retrieves subdomains from the ThreatMiner API.

    Args:
        domain (str): The domain to query for subdomains.

    Returns:
        List[str]: A list of subdomain strings found.
    """
    url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
    try:
        response = await async_client.get(url)
        response.raise_for_status()
        data = response.json()
        if data.get("status_code") == "200":
            return data.get("results", [])
        return []
    except (RequestError, HTTPStatusError) as e:
        logger.error(
            "Error fetching subdomains from ThreatMiner for '%s': %s", domain, e
        )
        return []


async def get_subdomains_urlscan(domain: str) -> List[str]:
    """
    Asynchronously retrieves subdomains from the URLScan.io API.

    Args:
        domain (str): The domain to query for subdomains.

    Returns:
        List[str]: A list of subdomain strings found.
    """
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    try:
        response = await async_client.get(url)
        response.raise_for_status()
        data = response.json()
        subdomains = {
            result["page"]["domain"]
            for result in data.get("results", [])
            if "page" in result and "domain" in result["page"]
        }
        return list(subdomains)
    except (RequestError, HTTPStatusError) as e:
        logger.error(
            "Error fetching subdomains from URLScan.io for '%s': %s", domain, e
        )
        return []


async def get_subdomains_shodan(domain: str, api_key: str) -> List[str]:
    """
    Asynchronously retrieves subdomains from the Shodan API.

    Args:
        domain (str): The domain to query for subdomains.
        api_key (str): The Shodan API key.

    Returns:
        List[str]: A list of subdomain strings found.
    """
    if not api_key:
        return []

    def search() -> List[str]:
        try:
            api = shodan.Shodan(api_key)
            query = f"hostname:.{domain}"
            result = api.search(query, limit=500)
            hostnames = {
                host["hostnames"][0]
                for host in result["matches"]
                if host.get("hostnames")
            }
            return list(hostnames)
        except Exception as e:
            logger.error(
                "Error fetching subdomains from Shodan for '%s': %s", domain, e
            )
            return []

    return await asyncio.to_thread(search)


# --- Core Logic Function ---


async def gather_footprint_data(domain: str) -> FootprintResult:
    """
    The core logic for gathering all footprint data and enriching it with threat intelligence.

    Args:
        domain (str): The target domain for the footprint scan.

    Returns:
        FootprintResult: A Pydantic model containing all the gathered and processed data.
    """
    # --- Stage 1: Initial Data Gathering ---

    vt_api_key = API_KEYS.virustotal_api_key
    shodan_api_key = API_KEYS.shodan_api_key

    initial_tasks = [
        (
            get_subdomains_virustotal(domain, vt_api_key)
            if vt_api_key
            else asyncio.sleep(0, result=[])
        ),
        get_subdomains_dnsdumpster(domain),
        get_subdomains_threatminer(domain),
        get_subdomains_urlscan(domain),
        (
            get_subdomains_shodan(domain, shodan_api_key)
            if shodan_api_key
            else asyncio.sleep(0, result=[])
        ),
        asyncio.to_thread(get_whois_info, domain),
        asyncio.to_thread(get_dns_records, domain),
    ]

    results = await asyncio.gather(*initial_tasks)
    vt, dd, tm, us, sh, whois_data, dns_data = results

    # --- Stage 2: Consolidate and Prepare for Enrichment ---

    all_subdomains: Dict[str, List[str]] = {}
    if isinstance(vt, list):
        for sub in vt:
            all_subdomains.setdefault(sub, []).append("VirusTotal")
    if isinstance(dd, list):
        for sub in dd:
            all_subdomains.setdefault(sub, []).append("DNSDumpster")
    if isinstance(tm, list):
        for sub in tm:
            all_subdomains.setdefault(sub, []).append("ThreatMiner")
    if isinstance(us, list):
        for sub in us:
            all_subdomains.setdefault(sub, []).append("URLScan.io")
    if isinstance(sh, list):
        for sub in sh:
            all_subdomains.setdefault(sub, []).append("Shodan")
    # Collect all unique indicators (IPs and subdomains) for threat intel lookup

    indicators_to_check = set(all_subdomains.keys())
    main_domain_ips = (
        dns_data.get("A", []) if isinstance(dns_data, dict) and dns_data else []
    )
    for ip in main_domain_ips:
        indicators_to_check.add(ip)
    # --- Stage 3: Threat Intelligence Enrichment ---

    threat_intel_results: Dict[str, Any] = {}
    if API_KEYS.otx_api_key:
        with console.status(
            "[bold cyan]Correlating findings with threat intelligence...[/bold cyan]"
        ):
            threat_intel_tasks = [
                get_threat_intel_otx(indicator) for indicator in indicators_to_check
            ]
            ti_results = await asyncio.gather(*threat_intel_tasks)
            for res in ti_results:
                if res:
                    threat_intel_results[res.indicator] = res
    # --- Stage 4: Final Assembly ---

    available_sources = sum(1 for key in [vt_api_key, shodan_api_key] if key) + 3
    scored_results = [
        ScoredResult(
            domain=sub,
            sources=sources,
            confidence=f"{'HIGH' if len(sources) > 1 else 'LOW'} ({len(sources)}/{available_sources} sources)",
            threat_intel=threat_intel_results.get(sub),
        )
        for sub, sources in sorted(all_subdomains.items())
    ]

    ip_threat_intelligence = [
        threat_intel_results[ip] for ip in main_domain_ips if ip in threat_intel_results
    ]

    subdomain_report = SubdomainReport(
        total_unique=len(scored_results), results=scored_results
    )
    footprint_data = FootprintData(
        whois_info=whois_data if isinstance(whois_data, dict) else {},
        dns_records=dns_data if isinstance(dns_data, dict) else {},
        subdomains=subdomain_report,
        ip_threat_intelligence=ip_threat_intelligence,
    )
    return FootprintResult(domain=domain, footprint=footprint_data)


# --- Typer CLI Application ---


footprint_app = typer.Typer()


@footprint_app.command("run")
def run_footprint_scan(
    domain: str = typer.Argument(..., help="The target domain, e.g., 'google.com'"),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """
    Gathers basic digital footprint information for a domain.

    Args:
        domain (str): The target domain, e.g., 'google.com'.
        output_file (str | None): Optional path to save the results to a JSON file.
    """
    if not is_valid_domain(domain):
        logger.warning(
            "Invalid domain format provided to 'footprint' command: %s", domain
        )
        console.print(
            Panel(
                f"[bold red]Invalid Input:[/] '{domain}' is not a valid domain format.",
                title="Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    logger.info("Starting asynchronous footprint scan for %s", domain)

    results_model = asyncio.run(gather_footprint_data(domain))
    results_dict = results_model.model_dump()

    logger.info("Footprint scan complete for %s", domain)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=domain, module="footprint", data=results_dict)
