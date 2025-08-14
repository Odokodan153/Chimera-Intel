import typer
import whois
import dns.resolver
import asyncio
from rich.panel import Panel
from dotenv import load_dotenv
from securitytrails import SecurityTrails
from typing import Dict, Any, List

# --- CORRECTED Absolute Imports ---
from chimera_intel.core.utils import console, save_or_print_results, is_valid_domain
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.config_loader import CONFIG, API_KEYS
from chimera_intel.core.schemas import FootprintResult, FootprintData, SubdomainReport, ScoredResult
from chimera_intel.core.http_client import async_client

# Load environment variables from the .env file
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
        return dict(domain_info) if domain_info.domain_name else {"error": "No WHOIS record found."}
    except Exception as e:
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
    # --- CHANGE: Access the config via attributes instead of dictionary keys ---
    record_types = CONFIG.modules.footprint.dns_records_to_query
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            dns_results[record_type] = [str(r.to_text()).strip('"') for r in answers]
        except dns.resolver.NoAnswer:
            dns_results[record_type] = None
        except dns.resolver.NXDOMAIN:
            return {"error": f"Domain does not exist (NXDOMAIN): {domain}"}
        except Exception as e:
            dns_results[record_type] = [f"Could not resolve {record_type}: {e}"]
    return dns_results

# --- Asynchronous Data Gathering Functions ---

async def get_subdomains_virustotal(domain: str, api_key: str) -> List[str]:
    """
    Asynchronously retrieves subdomains from the VirusTotal API using the central client.

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
    except Exception as e:
        console.print(f"[bold red]Error (VirusTotal):[/] {e}")
        return []

def get_subdomains_securitytrails(domain: str, api_key: str) -> List[str]:
    """
    Retrieves subdomains from the SecurityTrails API (synchronous library).

    Args:
        domain (str): The domain to query for subdomains.
        api_key (str): The SecurityTrails API key.

    Returns:
        List[str]: A list of subdomain strings found.
    """
    if not api_key:
        return []
    try:
        st = SecurityTrails(api_key)
        data = st.domain_subdomains(domain)
        return [f"{sub}.{domain}" for sub in data.get('subdomains', [])]
    except Exception as e:
        console.print(f"[bold red]Error (SecurityTrails):[/] {e}")
        return []

# --- Core Logic Function ---

async def gather_footprint_data(domain: str) -> FootprintResult:
    """
    The core logic for gathering all footprint data asynchronously.

    This function orchestrates the calls to various services (WHOIS, DNS, VirusTotal,
    SecurityTrails), aggregates the results, scores them, and returns a single,
    structured Pydantic model.

    Args:
        domain (str): The target domain for the footprint scan.

    Returns:
        FootprintResult: A Pydantic model containing all the gathered and processed data.
    """
    vt_api_key = API_KEYS.virustotal_api_key
    st_api_key = API_KEYS.securitytrails_api_key
    available_sources = sum(1 for key in [vt_api_key, st_api_key] if key)

    # Run async and sync tasks
    vt_subdomains = await get_subdomains_virustotal(domain, vt_api_key)
    whois_data = get_whois_info(domain)
    dns_data = get_dns_records(domain)
    st_subdomains = get_subdomains_securitytrails(domain, st_api_key)

    all_subdomains: Dict[str, List[str]] = {}
    for sub in vt_subdomains:
        all_subdomains.setdefault(sub, []).append("VirusTotal")
    for sub in st_subdomains:
        all_subdomains.setdefault(sub, []).append("SecurityTrails")
    
    scored_results = []
    for sub, sources in sorted(all_subdomains.items()):
        num_found_sources = len(sources)
        confidence = "HIGH" if available_sources > 1 and num_found_sources == available_sources else "LOW"
        scored_results.append(
            ScoredResult(domain=sub, sources=sources, confidence=f"{confidence} ({num_found_sources}/{available_sources} sources)")
        )

    subdomain_report = SubdomainReport(total_unique=len(scored_results), results=scored_results)
    footprint_data = FootprintData(
        whois_info=whois_data,
        dns_records=dns_data,
        subdomains=subdomain_report
    )
    return FootprintResult(domain=domain, footprint=footprint_data)

# --- Typer CLI Application ---
footprint_app = typer.Typer()

@footprint_app.command("run")
async def run_footprint_scan(
    domain: str = typer.Argument(..., help="The target domain, e.g., 'google.com'"),
    output_file: str = typer.Option(None, "--output", "-o", help="Save the results to a JSON file.")
):
    """
    Gathers basic digital footprint information for a domain.
    """
    if not is_valid_domain(domain):
        console.print(Panel(f"[bold red]Invalid Input:[/] '{domain}' is not a valid domain format.", title="Error", border_style="red"))
        raise typer.Exit(code=1)

    console.print(Panel(f"[bold green]Starting Asynchronous Footprint Scan For:[/] [yellow]{domain}[/yellow]", title="Chimera Intel | Footprint", border_style="blue"))
    
    results_model = await gather_footprint_data(domain)
    results_dict = results_model.model_dump()
    
    console.print("\n[bold green]Scan Complete![/bold green]")
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=domain, module="footprint", data=results_dict)