import typer
import whois
import dns.resolver
import re
import os
import requests
from rich.panel import Panel
from dotenv import load_dotenv
from securitytrails import SecurityTrails
from .utils import console, save_or_print_results

load_dotenv()

def is_valid_domain(domain: str) -> bool:
    """Validates if the given string is a plausible domain name."""
    if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", domain):
        return True
    return False

def get_whois_info(domain: str) -> dict:
    """Retrieves WHOIS information for a given domain."""
    try:
        domain_info = whois.whois(domain)
        return dict(domain_info) if domain_info.domain_name else {"error": "No WHOIS record found."}
    except Exception as e:
        return {"error": f"An exception occurred during WHOIS lookup: {e}"}

def get_dns_records(domain: str) -> dict:
    """Retrieves common DNS records for a given domain."""
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

# --- Subdomain Functions for Multiple Sources ---

def get_subdomains_virustotal(domain: str, api_key: str) -> list:
    """Retrieves subdomains from the VirusTotal API. Returns a list of domains."""
    if not api_key:
        console.print("[bold yellow]Warning:[/] VirusTotal API key not found. Skipping.")
        return []
    subdomains = []
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        for item in data.get("data", []):
            subdomains.append(item.get("id"))
        return subdomains
    except Exception as e:
        console.print(f"[bold red]Error (VirusTotal):[/] {e}")
        return []

def get_subdomains_securitytrails(domain: str, api_key: str) -> list:
    """Retrieves subdomains from the SecurityTrails API. Returns a list of domains."""
    if not api_key:
        console.print("[bold yellow]Warning:[/] SecurityTrails API key not found. Skipping.")
        return []
    try:
        st = SecurityTrails(api_key)
        data = st.domain_subdomains(domain)
        # The API returns a list of FQDNs, so we append '.domain' to them
        return [f"{sub}.{domain}" for sub in data.get('subdomains', [])]
    except Exception as e:
        console.print(f"[bold red]Error (SecurityTrails):[/] {e}")
        return []

# --- Typer CLI Application ---

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
    
    # --- Get API Keys ---
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    st_api_key = os.getenv("SECURITYTRAILS_API_KEY")
    available_sources = sum(1 for key in [vt_api_key, st_api_key] if key)

    # --- Gather Basic Data ---
    console.print(" [cyan]>[/cyan] Fetching WHOIS data...")
    whois_data = get_whois_info(domain)
    
    console.print(" [cyan]>[/cyan] Fetching DNS records...")
    dns_data = get_dns_records(domain)
    
    # --- Gather Subdomains from All Sources ---
    console.print(" [cyan]>[/cyan] Fetching subdomains from all available sources...")
    vt_subdomains = get_subdomains_virustotal(domain, vt_api_key)
    st_subdomains = get_subdomains_securitytrails(domain, st_api_key)

    # --- Aggregate and Score Subdomain Data ---
    console.print(" [cyan]>[/cyan] Aggregating subdomain results and calculating confidence...")
    all_subdomains = {}
    # Populate the dictionary with sources
    for sub in vt_subdomains:
        all_subdomains.setdefault(sub, []).append("VirusTotal")
    for sub in st_subdomains:
        all_subdomains.setdefault(sub, []).append("SecurityTrails")
    
    scored_results = []
    for sub, sources in all_subdomains.items():
        num_found_sources = len(sources)
        confidence = "LOW"
        if num_found_sources == available_sources and available_sources > 0:
            confidence = "HIGH"
        elif num_found_sources > 1:
            confidence = "MEDIUM"

        scored_results.append({
            "domain": sub,
            "sources": sources,
            "confidence": f"{confidence} ({num_found_sources}/{available_sources} sources)"
        })

    subdomain_report = {
        "total_unique": len(scored_results),
        "results": scored_results
    }

    # --- Structure the final results ---
    results = {
        "domain": domain,
        "footprint": {
            "whois_info": whois_data,
            "dns_records": dns_data,
            "subdomains": subdomain_report
        }
    }

    console.print("\n[bold green]Scan Complete![/bold green]")
    save_or_print_results(results, output_file)