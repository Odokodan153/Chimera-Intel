import typer
import os
import json
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from .database import get_aggregated_data_for_target

console = Console()

# Define keywords that might signal strategic intent in different areas.
SIGNAL_KEYWORDS = {
    "Marketing & Sales": ["HubSpot", "Marketo", "Salesforce", "CRM", "Pardot", "Drift"],
    "Technology & Engineering": ["Kubernetes", "Terraform", "AWS Lambda", "Go", "Rust", "Microservices", "Data Scientist"],
    "Expansion & Growth": ["Country Manager", "International", "Logistics", "Supply Chain", "New Market"],
    "HR & Culture": ["Head of People", "Culture", "Chief Happiness Officer"]
}

def scrape_job_postings(domain: str) -> dict:
    """
    A simple scraper to find potential job titles from a 'careers' page.
    NOTE: This is a highly generic scraper and may need to be adapted for specific sites.

    Args:
        domain (str): The domain to find a careers page for.

    Returns:
        dict: A dictionary containing a list of found job titles, or an error.
    """
    urls_to_try = [f"https://www.{domain}/careers", f"https://www.{domain}/jobs", f"https://boards.greenhouse.io/{domain}"]
    headers = {"User-Agent": "Mozilla/5.0"}
    job_titles = []

    for url in urls_to_try:
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                # A generic search for tags that often contain job titles.
                # This is a best-effort approach.
                for tag in soup.find_all(['h2', 'h3', 'a', 'div'], class_=lambda x: x and 'job' in x.lower()):
                    job_titles.append(tag.text.strip())
                
                # If we found jobs on the first successful URL, we can stop.
                if job_titles:
                    return {"job_postings": list(set(job_titles))} # Return unique titles
        except requests.RequestException:
            # Ignore connection errors and try the next URL
            continue
            
    return {"job_postings": list(set(job_titles))}

def analyze_signals(aggregated_data: dict) -> list[tuple[str, str, str]]:
    """
    Applies a rule-based engine to find and categorize strategic signals in OSINT data.

    Args:
        aggregated_data (dict): The combined OSINT data for the target.

    Returns:
        list[tuple[str, str, str]]: A list of tuples, each containing the category,
                                     signal, and the source of the data.
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
    
    # You can add more signal analysis rules here (e.g., from news, patents, etc.)

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