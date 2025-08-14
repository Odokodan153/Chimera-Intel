import typer
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typing import List

# --- CORRECTED Absolute Imports ---
from chimera_intel.core.database import get_aggregated_data_for_target
from chimera_intel.core.http_client import sync_client
from chimera_intel.core.utils import is_valid_domain, console
# --- CHANGE: Import the new Pydantic models ---
from chimera_intel.core.schemas import JobPostingsResult, StrategicSignal


# Define keywords that might signal strategic intent in different areas.
SIGNAL_KEYWORDS = {
    "Marketing & Sales": ["HubSpot", "Marketo", "Salesforce", "CRM", "Pardot", "Drift"],
    "Technology & Engineering": ["Kubernetes", "Terraform", "AWS Lambda", "Go", "Rust", "Microservices", "Data Scientist"],
    "Expansion & Growth": ["Country Manager", "International", "Logistics", "Supply Chain", "New Market"],
    "HR & Culture": ["Head of People", "Culture", "Chief Happiness Officer"]
}

def scrape_job_postings(domain: str) -> JobPostingsResult:
    """
    Scrapes a target's potential careers pages to find job postings.

    This is a generic scraper that tries common URL paths for job/career pages.
    It may need to be adapted for specific, non-standard site structures.

    Args:
        domain (str): The domain to find a careers page for.

    Returns:
        JobPostingsResult: A Pydantic model containing a list of unique job titles found or an error.
    """
    urls_to_try = [f"https://www.{domain}/careers", f"https://www.{domain}/jobs", f"https://boards.greenhouse.io/{domain}"]
    headers = {"User-Agent": "Mozilla/5.0"}
    job_titles: List[str] = []

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
                    return JobPostingsResult(job_postings=list(set(job_titles)))
        except Exception:
            # Ignore connection errors and try the next URL
            continue
            
    return JobPostingsResult(job_postings=list(set(job_titles)))

def analyze_signals(aggregated_data: dict) -> List[StrategicSignal]:
    """
    Applies a rule-based engine to find and categorize strategic signals in OSINT data.

    It scans through technology stack information and job postings (if available)
    for keywords defined in the SIGNAL_KEYWORDS dictionary.

    Args:
        aggregated_data (dict): The combined OSINT data for the target.

    Returns:
        List[StrategicSignal]: A list of Pydantic models, each representing a detected signal.
    """
    signals: List[StrategicSignal] = []
    
    # 1. Analyze Technology Stack for signals
    tech_data = aggregated_data.get("modules", {}).get("web_analyzer", {}).get("web_analysis", {}).get("tech_stack", {}).get("results", [])
    for tech_item in tech_data:
        tech_name = tech_item.get("technology")
        for category, keywords in SIGNAL_KEYWORDS.items():
            for keyword in keywords:
                if isinstance(tech_name, str) and keyword.lower() in tech_name.lower():
                    signals.append(
                        StrategicSignal(
                            category=category,
                            signal=f"Adoption of '{tech_name}' technology detected.",
                            source="Web Technology Stack"
                        )
                    )

    # 2. Analyze Job Postings for signals
    job_postings = aggregated_data.get("job_postings", {}).get("job_postings", [])
    for job_title in job_postings:
        for category, keywords in SIGNAL_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in job_title.lower():
                    signals.append(
                        StrategicSignal(
                            category=category,
                            signal=f"Hiring for role: '{job_title}'.",
                            source="Job Postings"
                        )
                    )
    
    return signals

# --- Typer CLI Application ---

signal_app = typer.Typer()

@signal_app.command("run")
def run_signal_analysis(
    target: str = typer.Argument(..., help="The target domain to analyze for strategic signals.")
):
    """
    Analyzes a target's public footprint for unintentional strategic signals.
    
    This command aggregates historical data, performs a live scrape for job postings,
    and then analyzes the combined data to detect potential strategic movements
    based on a predefined set of keywords and rules.
    """
    if not is_valid_domain(target):
        console.print(Panel(f"[bold red]Invalid Input:[/] '{target}' is not a valid domain format.", title="Error", border_style="red"))
        raise typer.Exit(code=1)

    console.print(Panel(f"[bold yellow]Analyzing Strategic Signals For:[/] {target}", title="Chimera Intel | Signal Analysis", border_style="yellow"))

    console.print(f" [dim]>[/dim] [dim]Aggregating historical data for '{target}'...[/dim]")
    aggregated_data = get_aggregated_data_for_target(target)
    
    if not aggregated_data:
        # The get_aggregated_data_for_target function already prints a warning.
        raise typer.Exit()
    
    console.print(f" [dim]>[/dim] [dim]Performing a live scrape for job postings...[/dim]")
    # The result is a Pydantic model, convert it to a dict to merge it.
    job_results = scrape_job_postings(target)
    aggregated_data["job_postings"] = job_results.model_dump()
        
    console.print(f" [dim]>[/dim] [dim]Analyzing data for strategic signals...[/dim]")
    detected_signals = analyze_signals(aggregated_data)
    
    if not detected_signals:
        console.print("\n[bold green]No strong strategic signals detected based on the current rule set.[/bold green]")
        raise typer.Exit()

    table = Table(title=f"Potential Strategic Signals Detected for {target}")
    table.add_column("Category", style="magenta")
    table.add_column("Signal Detected", style="cyan")
    table.add_column("Source", style="green")
    
    for signal_model in detected_signals:
        table.add_row(signal_model.category, signal_model.signal, signal_model.source)
        
    console.print(table)