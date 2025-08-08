import typer
import os
import requests
import json
from rich.console import Console
from rich.json import JSON

console = Console()

# --- Data Gathering Functions for Web Analysis ---

def get_tech_stack_builtwith(domain: str, api_key: str) -> dict:
    """Retrieves website technology stack from the BuiltWith API."""
    if not api_key:
        return {"error": "BuiltWith API key not found."}
        
    url = f"https://api.builtwith.com/v21/api.json?KEY={api_key}&LOOKUP={domain}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP error occurred: {e}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}

def get_traffic_similarweb(domain: str, api_key: str) -> dict:
    """Retrieves estimated website traffic from the Similarweb API."""
    if not api_key:
        return {"error": "Similarweb API key not found."}

    # Note: This is a simplified example. Similarweb has multiple endpoints.
    # This uses the 'visits' endpoint as an illustration.
    url = f"https://api.similarweb.com/v1/website/{domain}/total-traffic-and-engagement/visits?api_key={api_key}&granularity=monthly&main_domain_only=false"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP error occurred: {e}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}

# --- Typer CLI Application for this module ---

web_app = typer.Typer()

@web_app.command("run")
def run_web_analysis(
    domain: str = typer.Argument(..., help="The target domain to analyze."),
):
    """
    Analyzes web-specific data: tech stack and traffic.
    """
    console.print(f"\n[bold blue]--- Starting Web Analysis for {domain} ---[/bold blue]")
    
    # Get API Keys
    builtwith_key = os.getenv("BUILTWITH_API_KEY")
    similarweb_key = os.getenv("SIMILARWEB_API_KEY")

    # --- Data Gathering ---
    console.print(" [cyan]>[/cyan] Fetching Technology Stack...")
    tech_stack = get_tech_stack_builtwith(domain, builtwith_key)
    
    console.print(" [cyan]>[/cyan] Fetching Traffic Information...")
    traffic_info = get_traffic_similarweb(domain, similarweb_key)

    # --- Structure and Print Results ---
    results = {
        "domain": domain,
        "web_analysis": {
            "tech_stack": tech_stack,
            "traffic_info": traffic_info,
        }
    }
    
    json_str = json.dumps(results, indent=4, ensure_ascii=False, default=str)
    console.print(JSON(json_str))