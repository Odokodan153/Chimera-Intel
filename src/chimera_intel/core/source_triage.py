"""
Module for Source Triage & OSINT Checklist.

Provides tools to perform quick, automated checks on a URL to
determine its origin, age, and basic content profile.

This module uses Playwright to render dynamic JavaScript content
for more accurate scraping of social media sites.
"""

import typer
import logging
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
import whois
from bs4 import BeautifulSoup
import re
from rich.console import Console
from playwright.sync_api import sync_playwright, Error as PlaywrightError
from .utils import save_or_print_results
from .schemas import SourceTriageResult

logger = logging.getLogger(__name__)
console = Console()
triage_app = typer.Typer(
    name="source-triage",
    help="Run OSINT triage checks on a source URL.",
)

# Standard User-Agent to avoid simple bot blocking
CHROME_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"


def get_source_triage(url: str) -> SourceTriageResult:
    """
    Performs OSINT triage on a given URL.
    """
    result = SourceTriageResult(url=url, domain="Unknown")
    
    # 1. Parse domain using urllib (more robust than regex)
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain:
            raise ValueError("Could not parse domain from URL.")
        # Remove 'www.' prefix if it exists
        if domain.startswith("www."):
            domain = domain[4:]
        result.domain = domain
    except Exception as e:
        result.error = f"Failed to parse URL: {e}"
        return result

    # 2. Check domain age (WHOIS)
    try:
        domain_info = whois.query(domain)
        if domain_info and domain_info.creation_date:
            c_date = domain_info.creation_date
            if isinstance(c_date, list):
                c_date = c_date[0]
            
            if c_date:
                result.domain_creation_date = c_date
                age = (datetime.now() - c_date).days
                result.domain_age_days = age
                if age < 180:
                    result.indicators.append(f"Domain is very new ({age} days old)")
    except Exception as e:
        logger.warning(f"WHOIS check failed for {domain}: {e}")
        result.indicators.append(f"WHOIS lookup failed (this is common): {str(e)[:50]}...")

    # 3. Scrape page using Playwright to render JavaScript
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context(user_agent=CHROME_USER_AGENT)
            page = context.new_page()
            
            # Go to page, wait for network to be idle, 15 sec timeout
            page.goto(url, wait_until="networkidle", timeout=15000)
            
            # Get rendered HTML content and title
            html_content = page.content()
            result.page_title = page.title().strip()
            
            browser.close()

            # 4. Parse the rendered HTML with BeautifulSoup
            soup = BeautifulSoup(html_content, "html.parser")
            text_lower = soup.get_text().lower()

            # --- Heuristics for Social Media (now on rendered content) ---
            if "twitter.com" in domain or "x.com" in domain:
                result.is_social_media = True
                # Look for "Joined Month YYYY"
                join_match = re.search(r"joined (\w+ \d{4})", text_lower)
                if join_match:
                    result.profile_details["Joined"] = join_match.group(1)
                
            elif "reddit.com" in domain:
                result.is_social_media = True
                # Look for karma
                karma_match = re.search(r"(\d+[,.]?\d*k?)\s+post karma", text_lower)
                if karma_match:
                    result.profile_details["Post Karma"] = karma_match.group(1)
                
            elif "facebook.com" in domain:
                result.is_social_media = True
                result.profile_details["Platform"] = "Facebook"
            
            if "followers" in text_lower:
                result.indicators.append("Page contains 'followers' keyword.")

    except PlaywrightError as e:
        result.error = f"Failed to scrape URL with Playwright: {e}"
        result.indicators.append("Dynamic page scraping failed.")
    except Exception as e:
        # Catch any other unexpected errors during scraping
        result.error = f"An unexpected error occurred during scraping: {e}"
        result.indicators.append("Page analysis failed.")

    return result


@triage_app.command("run", help="Run triage checks on a source URL.")
def cli_run_source_triage(
    url: str = typer.Argument(..., help="The source URL to check."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    CLI command to run the source triage analysis.
    """
    console.print(f"Running source triage on: [bold cyan]{url}[/bold cyan]")
    result = get_source_triage(url)
    
    results_dict = result.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file, console)
    
    if result.error:
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    triage_app()