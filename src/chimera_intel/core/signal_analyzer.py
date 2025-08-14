import typer
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typing import Dict, Any, List, Tuple

# --- CORRECTED Absolute Imports ---
from chimera_intel.core.database import get_aggregated_data_for_target
from chimera_intel.core.http_client import sync_client
from chimera_intel.core.utils import is_valid_domain, console

console = Console()

# Define keywords that might signal strategic intent in different areas.
SIGNAL_KEYWORDS = {
    "Marketing & Sales": ["HubSpot", "Marketo", "Salesforce", "CRM", "Pardot", "Drift"],
    "Technology & Engineering": ["Kubernetes", "Terraform", "AWS Lambda", "Go", "Rust", "Microservices", "Data Scientist"],
    "Expansion & Growth": ["Country Manager", "International", "Logistics", "Supply Chain", "New Market"],
    "HR & Culture": ["Head of People", "Culture", "Chief Happiness Officer"]
}

def scrape_job_postings(domain: str) -> Dict[str, Any]:
    """
    Scrapes a target's potential careers pages to find job postings.

    This is a generic scraper that tries common URL paths for job/career pages.
    It may need to be adapted for specific, non-standard site structures.

    Args:
        domain (str): The domain to find a careers page for.

    Returns:
        Dict[str, Any]: A dictionary containing a list of unique job titles found.
    """
    urls_to_try = [f"https://www.{domain}/careers", f"https://www.{domain}/jobs", f"https://boards.greenhouse.io/{domain}"]
    headers = {"User-Agent": "Mozilla/5.0"}
    job_titles = []

    for url in urls_to_try:
        try:
            response = sync_client.get(url, headers=headers)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                # A generic search for tags that often contain job titles.
                for tag in soup.find_all(['h2', 'h3', 'a', 'div'], class_=lambda x: x and 'job' in x.lower()):
                    job_titles.append(tag.text.strip())
                
                # If we found jobs on the first successful URL, we can stop.
                if job_titles:
                    return {"job_postings": list(set(job_titles))}
        except Exception:
            # Ignore connection errors and try the next URL
            continue
            
    return {"job_postings": list(set(job_titles))}

def analyze_signals(aggregated_data: dict) -> List[Tuple[str, str, str]]:
    """
    Applies a rule-based engine to find and categorize strategic signals in OSINT data.

    It scans through technology stack information and job postings (if available)
    for keywords defined in the SIGNAL_KEYWORDS dictionary.

    Args:
        aggregated_data (dict): The combined OSINT data for the target.

    Returns:
        List[Tuple[str, str, str]]: A list of tuples, each containing the signal category,
                                     the specific signal detected, and its data source.
    """
    signals = []
    
    # 1. Analyze Technology Stack for signals
    tech_data = aggregated_data.get("modules", {}).get("web_analyzer", {}).get("web_analysis", {}).get("tech_stack", {}).get("results", [])
    for tech_item in tech_data:
        tech_name = tech_item.get("technology")
        for category, keywords in SIGNAL_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in tech_name.lower():
                    signals.append((category, f"Adoption of '{tech_name}' technology detected.", "Web Technology Stack"))

    # 2. Analyze Job Postings for signals
    job_data = aggregated_data.get("job_postings", {}).get("job_postings", [])
    for job_title in job_data:
        for category, keywords in SIGNAL_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in job_title.lower():
                    signals.append((category, f"Hiring for role: '{job_title}'.", "Job Postings"))
    
    return signals

# --- Typer CLI Application ---

signal_app = typer.Typer()

@signal_app.command("run")
def run_signal_analysis(
    target: str = typer.Argument(..., help="The target domain to analyze for strategic signals.")
):
    """
    Analyzes a target's public footprint for unintentional strategic signals.
    """
    # First, validate the input to ensure it's a correctly formatted domain.
    if not is_valid_domain(target):
        console.print(Panel(f"[bold red]Invalid Input:[/] '{target}' is not a valid domain format.", title="Error", border_style="red"))
        raise typer.Exit(code=1)

    console.print(Panel(f"[bold yellow]Analyzing Strategic Signals For:[/] {target}", title="Chimera Intel | Signal Analysis", border_style="yellow"))

    # Step 1: Aggregate all available data from the database
    console.print(f" [dim]>[/dim] [dim]Aggregating historical data for '{target}'...[/dim]")
    aggregated_data = get_aggregated_data_for_target(target)
    
    if not aggregated_data:
        raise typer.Exit()
    
    # Step 2: Scrape for job postings (as this is not part of our regular scans yet)
    console.print(f" [dim]>[/dim] [dim]Performing a live scrape for job postings...[/dim]")
    aggregated_data["job_postings"] = scrape_job_postings(target)
        
    # Step 3: Run the data through our signal analysis engine
    console.print(f" [dim]>[/dim] [dim]Analyzing data for strategic signals...[/dim]")
    detected_signals = analyze_signals(aggregated_data)
    
    # Step 4: Display the results in a clean table
    table = Table(title=f"Potential Strategic Signals Detected for {target}")
    table.add_column("Category", style="magenta")
    table.add_column("Signal Detected", style="cyan")
    table.add_column("Source", style="green")
    
    if not detected_signals:
        console.print("[bold green]No strong strategic signals detected based on the current rule set.[/bold green]")
        raise typer.Exit()

    for category, signal, source in detected_signals:
        table.add_row(category, signal, source)
        
    console.print(table)