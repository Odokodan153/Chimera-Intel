import typer
import os
import requests
from rich.panel import Panel
from .utils import console, save_or_print_results

def get_tech_stack_builtwith(domain: str, api_key: str) -> dict:
    """Retrieves website technology stack from the BuiltWith API.

    Args:
        domain (str): The domain to query.
        api_key (str): The BuiltWith API key.

    Returns:
        dict: A dictionary containing the technology stack, or an error message.
    """
    if not api_key:
        return {"error": "BuiltWith API key not found."}
        
    url = f"[https://api.builtwith.com/v21/api.json?KEY=](https://api.builtwith.com/v21/api.json?KEY=){api_key}&LOOKUP={domain}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP error occurred: {e}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}

def get_traffic_similarweb(domain: str, api_key: str) -> dict:
    """Retrieves estimated website traffic from the Similarweb API.

    Args:
        domain (str): The domain to query.
        api_key (str): The Similarweb API key.

    Returns:
        dict: A dictionary containing traffic data, or an error message.
    """
    if not api_key:
        return {"error": "Similarweb API key not found."}

    url = f"[https://api.similarweb.com/v1/website/](https://api.similarweb.com/v1/website/){domain}/total-traffic-and-engagement/visits?api_key={api_key}&granularity=monthly&main_domain_only=false"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP error occurred: {e}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}


web_app = typer.Typer()

@web_app.command("run")
def run_web_analysis(
    domain: str = typer.Argument(..., help="The target domain to analyze."),
    output_file: str = typer.Option(None, "--output", "-o", help="Save the results to a JSON file.")
):
    """Analyzes web-specific data: tech stack and traffic."""
    console.print(Panel(f"[bold blue]Starting Web Analysis for {domain}[/bold blue]", title="Chimera Intel | Web", border_style="blue"))
    
    builtwith_key = os.getenv("BUILTWITH_API_KEY")
    similarweb_key = os.getenv("SIMILARWEB_API_KEY")

    console.print(" [cyan]>[/cyan] Fetching Technology Stack...")
    tech_stack = get_tech_stack_builtwith(domain, builtwith_key)
    
    console.print(" [cyan]>[/cyan] Fetching Traffic Information...")
    traffic_info = get_traffic_similarweb(domain, similarweb_key)

    results = {
        "domain": domain,
        "web_analysis": {
            "tech_stack": tech_stack,
            "traffic_info": traffic_info,
        }
    }
    
    console.print("\n[bold green]Web Analysis Complete![/bold green]")
    save_or_print_results(results, output_file)