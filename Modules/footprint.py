import typer
import whois
import dns.resolver
import re
import json

from rich.console import Console
from rich.panel import Panel
from rich.json import JSON

# Initialize rich console for beautiful printing
console = Console()

# --- Helper and Validation Functions ---

def is_valid_domain(domain: str) -> bool:
    """
    Validates if the given string is a plausible domain name.
    """
    # This is a basic regex for domain validation.
    # It checks for a pattern like 'example.com' or 'sub.example.co.uk'
    if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", domain):
        return True
    return False

# --- Data Gathering Functions ---

def get_whois_info(domain: str) -> dict:
    """
    Retrieves WHOIS information for a given domain.
    Includes error handling for domains that don't exist or other issues.
    """
    try:
        domain_info = whois.whois(domain)
        # Check if the whois object contains any data
        if domain_info.domain_name:
            return dict(domain_info)
        else:
            return {"error": "No WHOIS record found. The domain may not exist or is private."}
    except Exception as e:
        console.print(f"[bold red]WHOIS Error:[/] {e}")
        return {"error": f"An exception occurred during WHOIS lookup: {e}"}

def get_dns_records(domain: str) -> dict:
    """
    Retrieves common DNS records for a given domain.
    """
    dns_results = {}
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            dns_results[record_type] = [str(r.to_text()).strip('"') for r in answers]
        except dns.resolver.NoAnswer:
            dns_results[record_type] = None # Use None to indicate no record found
        except dns.resolver.NXDOMAIN:
            # This error means the domain does not exist. We can stop here.
            return {"error": f"Domain does not exist (NXDOMAIN): {domain}"}
        except Exception as e:
            dns_results[record_type] = [f"Could not resolve {record_type}: {e}"]
            
    return dns_results

# --- Typer CLI Application for this module ---

footprint_app = typer.Typer()

@footprint_app.command("run")
def run_footprint_scan(
    domain: str = typer.Argument(..., help="The target domain, e.g., 'google.com'"),
    output_file: str = typer.Option(None, "--output", "-o", help="Save the results to a JSON file.")
):
    """
    Gathers the basic digital footprint of a domain (WHOIS, DNS records).
    """
    # Defensive Line: Validate the input domain format before doing anything else.
    if not is_valid_domain(domain):
        console.print(Panel(f"[bold red]Invalid Input:[/] '{domain}' is not a valid domain format.", title="Error", border_style="red"))
        raise typer.Exit(code=1)

    console.print(Panel(f"[bold green]Starting Footprint Scan For:[/] [yellow]{domain}[/yellow]", title="Chimera Intel", border_style="blue"))

    # Gather data
    console.print(" [cyan]>[/cyan] Fetching WHOIS data...")
    whois_data = get_whois_info(domain)
    
    console.print(" [cyan]>[/cyan] Fetching DNS records...")
    dns_data = get_dns_records(domain)

    # Structure the final results
    results = {
        "domain": domain,
        "footprint": {
            "whois_info": whois_data,
            "dns_records": dns_data
        }
    }

    console.print("\n[bold green]Scan Complete![/bold green]")
    
    # Handle output
    if output_file:
        console.print(f" [cyan]>[/cyan] Saving results to [yellow]{output_file}[/yellow]...")
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, ensure_ascii=False, default=str)
            console.print(f"[bold green]Successfully saved to {output_file}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Error saving file:[/] {e}")
    else:
        # Use rich's JSON pretty printer
        json_str = json.dumps(results, indent=4, ensure_ascii=False, default=str)
        console.print(JSON(json_str))