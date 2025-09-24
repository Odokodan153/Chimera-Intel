import typer
from bs4 import BeautifulSoup
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from typing import List, Optional
import logging
from httpx import RequestError, HTTPStatusError
from chimera_intel.core.database import get_aggregated_data_for_target
from chimera_intel.core.http_client import sync_client
from chimera_intel.core.utils import is_valid_domain, console
from chimera_intel.core.schemas import JobPostingsResult, StrategicSignal
from .project_manager import resolve_target

# Get a logger instance for this specific file


logger = logging.getLogger(__name__)

# Define keywords that might signal strategic intent in different areas.


SIGNAL_KEYWORDS = {
    "Marketing & Sales": ["HubSpot", "Marketo", "Salesforce", "CRM", "Pardot", "Drift"],
    "Technology & Engineering": [
        "Kubernetes",
        "Terraform",
        "AWS Lambda",
        "Go",
        "Rust",
        "Microservices",
        "Data Scientist",
    ],
    "Expansion & Growth": [
        "Country Manager",
        "International",
        "Logistics",
        "Supply Chain",
        "New Market",
    ],
    "HR & Culture": ["Head of People", "Culture", "Chief Happiness Officer"],
    "Financial Strategy": [
        "investment",
        "acquisition",
        "funding round",
        "merger",
        "ipo",
        "financial results",
    ],
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
    urls_to_try = [
        f"https://www.{domain}/careers",
        f"https://www.{domain}/jobs",
        f"https://boards.greenhouse.io/{domain}",
    ]
    headers = {"User-Agent": "Mozilla/5.0"}
    job_titles: List[str] = []

    for url in urls_to_try:
        try:
            response = sync_client.get(url, headers=headers)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                # A generic search for tags that often contain job titles.

                for tag in soup.find_all(
                    ["h2", "h3", "a", "div"], class_=lambda x: x and "job" in x.lower()
                ):
                    job_titles.append(tag.text.strip())
                # If we found jobs on the first successful URL, we can stop.

                if job_titles:
                    return JobPostingsResult(job_postings=list(set(job_titles)))
        except (HTTPStatusError, RequestError) as e:
            logger.warning("Could not scrape job postings from %s: %s", url, e)
            continue  # Try the next URL
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

    tech_data = (
        aggregated_data.get("modules", {})
        .get("web_analyzer", {})
        .get("web_analysis", {})
        .get("tech_stack", {})
        .get("results", [])
    )
    for tech_item in tech_data:
        tech_name = tech_item.get("technology")
        if not isinstance(tech_name, str):
            continue
        signal_found_for_tech = False
        for category, keywords in SIGNAL_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in tech_name.lower():
                    signals.append(
                        StrategicSignal(
                            category=category,
                            signal=f"Adoption of '{tech_name}' technology detected.",
                            source="Web Technology Stack",
                        )
                    )
                    signal_found_for_tech = True
                    break  # Stop checking other keywords in this category
            if signal_found_for_tech:
                break  # Stop checking other categories for this tech item
    # 2. Analyze Job Postings for signals

    job_postings = aggregated_data.get("job_postings", {}).get("job_postings", [])
    for job_title in job_postings:
        signal_found_for_job = False
        for category, keywords in SIGNAL_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in job_title.lower():
                    signals.append(
                        StrategicSignal(
                            category=category,
                            signal=f"Hiring for role: '{job_title}'.",
                            source="Job Postings",
                        )
                    )
                    signal_found_for_job = True
                    break  # Stop checking other keywords in this category
            if signal_found_for_job:
                break  # Stop checking other categories for this job title
    return signals


# --- Typer CLI Application ---


signal_app = typer.Typer()
# FIX: Create a dedicated console for stderr output


console_err = Console(stderr=True, style="bold yellow")


@signal_app.command("run")
def run_signal_analysis(
    target: Optional[str] = typer.Argument(
        None, help="The target domain to analyze. Uses active project if not provided."
    )
):
    """
    Analyzes a target's public footprint for unintentional strategic signals.
    """
    target_name = resolve_target(target, required_assets=["domain"])

    if not is_valid_domain(target_name):
        logger.warning(
            "Invalid domain format provided to 'signal' command: %s", target_name
        )
        console.print(
            Panel(
                f"[bold red]Invalid Input:[/] '{target_name}' is not a valid domain format.",
                title="Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    logger.info("Analyzing strategic signals for: %s", target_name)

    aggregated_data = get_aggregated_data_for_target(target_name)

    if not aggregated_data:
        # FIX: Use the dedicated stderr console

        console_err.print(
            f"No historical data found for '{target_name}'. Run a full scan first."
        )
        raise typer.Exit(code=1)
    logger.info("Performing a live scrape for job postings for %s.", target_name)
    job_results = scrape_job_postings(target_name)
    aggregated_data["job_postings"] = job_results.model_dump()

    logger.info("Analyzing data for strategic signals.")
    detected_signals = analyze_signals(aggregated_data)

    if not detected_signals:
        logger.info(
            "No strong strategic signals detected for %s based on the current rule set.",
            target_name,
        )
        # FIX: Use the dedicated stderr console

        console_err.print(
            "No strong strategic signals detected based on the current rule set."
        )
        raise typer.Exit()
    table = Table(title=f"Potential Strategic Signals Detected for {target_name}")
    table.add_column("Category", style="magenta")
    table.add_column("Signal Detected", style="cyan")
    table.add_column("Source", style="green")

    for signal_model in detected_signals:
        table.add_row(signal_model.category, signal_model.signal, signal_model.source)
    console.print(table)
