import typer
import whois
import dns.resolver
import re
import os
import requests
from rich.panel import Panel
from dotenv import load_dotenv
from .utils import console, save_or_print_results

load_dotenv()

def is_valid_domain(domain: str) -> bool:
    """Validates if the given string is a plausible domain name.

    Args:
        domain (str): The string to validate.

    Returns:
        bool: True if the string is a valid domain format, False otherwise.
    """
    if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", domain):
        return True
    return False

def get_whois_info(domain: str) -> dict:
    """Retrieves WHOIS information for a given domain.

    Args:
        domain (str): The domain to query.

    Returns:
        dict: A dictionary containing the WHOIS data, or an error message.
    """
    try:
        domain_info = whois.whois(domain)
        return dict(domain_info) if domain_info.domain_name else {"error": "No WHOIS record found."}
    except Exception as e:
        return {"error": f"An exception occurred during WHOIS lookup: {e}"}

def get_dns_records(domain: str) -> dict:
    """Retrieves common DNS records for a given domain.

    Args:
        domain (str): The domain to query.

    Returns:
        dict: A dictionary containing DNS records, or an error message.
    """
    dns_results = {}
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
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

def get_subdomains_virustotal(domain: str, api_key: str) -> dict:
    """Retrieves subdomains from the VirusTotal API.

    Args:
        domain (str): The domain to query.
        api_key (str): The VirusTotal API key.

    Returns:
        dict: A dictionary containing subdomains, or an error message.
    """
    if not api_key:
        return {"error": "VirusTotal API key not found."}
    subdomains = []
    headers = {"x-apikey": api_key}
    url = f"[https://www.virustotal.com/api/v3/domains/](https://www.virustotal.com/api/v3/domains/){domain}/subdomains?limit=100"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        for item in data.get("data", []):
            subdomains.append(item.get("id"))
        return {"subdomains": subdomains, "count": len(subdomains)}
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP error occurred: {e}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}


footprint_app = typer.Typer()

@footprint_app.command("run")
def run_footprint_scan(
    domain: str = typer.Argument(..., help="The target domain, e.g., 'google.com'"),
    output_file: str = typer.Option(None, "--output", "-o", help="Save the results to a JSON file.")
):
    """Gathers the basic digital footprint of a domain (WHOIS, DNS, Subdomains)."""
    if not is_valid_domain(domain):
        console.print(Panel(f"[bold red]Invalid Input:[/] '{domain}' is not a valid domain format.", title="Error", border_style="red"))
        raise typer.Exit(code=1)

    console.print(Panel(f"[bold green]Starting Footprint Scan For:[/] [yellow]{domain}[/yellow]", title="Chimera Intel", border_style="blue"))
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")

    console.print(" [cyan]>[/cyan] Fetching WHOIS data...")
    whois_data = get_whois_info(domain)
    
    console.print(" [cyan]>[/cyan] Fetching DNS records...")
    dns_data = get_dns_records(domain)
    
    subdomain_data = {"error": "VirusTotal API key not found."}
    if vt_api_key:
        console.print(" [cyan]>[/cyan] Fetching subdomains from VirusTotal...")
        subdomain_data = get_subdomains_virustotal(domain, vt_api_key)
    else:
        console.print("[bold yellow]Warning:[/] VIRUSTOTAL_API_KEY not found. Skipping subdomain scan.")

    results = {
        "domain": domain,
        "footprint": {
            "whois_info": whois_data,
            "dns_records": dns_data,
            "subdomains_virustotal": subdomain_data
        }
    }

    console.print("\n[bold green]Scan Complete![/bold green]")
    save_or_print_results(results, output_file)