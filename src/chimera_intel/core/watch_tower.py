"""
OSINT Watch Tower Module for Chimera Intel.

This module provides text-based "change detection" for web pages.
It is designed to monitor specific URLs (e.g., competitor careers pages,
product pages, sitemaps) and alert when new text snippets or links
are found, especially if they contain user-defined keywords.
"""

import typer
import logging
import json
import re
from typing import Optional, List, Dict, Set, Any, Tuple
from bs4 import BeautifulSoup

from .schemas import (
    ProjectConfig,
    PageMonitorConfig,
    TextDiffResult
)
from .utils import console
from .database import save_scan_to_db, get_db_connection
from .project_manager import list_projects, get_project_config_by_name
from .alert_manager import alert_manager_instance, AlertLevel
from .scheduler import add_job
from .http_client import sync_client

logger = logging.getLogger(__name__)

# --- Core Monitoring Logic ---

def _fetch_and_parse_page(url: str) -> tuple[Set[str], Set[str]]:
    """
    Fetches a URL and parses it into a set of text snippets and a set of links.
    """
    text_snippets = set()
    links = set()
    try:
        response = sync_client.get(url, follow_redirects=True, timeout=20.0)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')

        # 1. Extract all text snippets
        # We get text from common tags, strip it, and filter out empty strings
        for tag in soup.find_all(['p', 'li', 'a', 'h1', 'h2', 'h3', 'span', 'div']):
            text = tag.get_text(strip=True)
            if text:
                text_snippets.add(text)
                
        # 2. Extract all links
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith('http'): # Only care about absolute, external links
                links.add(href)
                
        return text_snippets, links
        
    except Exception as e:
        logger.warning(f"Failed to fetch or parse page {url}: {e}")
        return set(), set()


def _get_baseline_data(watch_id: str) -> tuple[Set[str], Set[str]]:
    """
    Retrieves the set of text snippets and links from the last successful run.
    """
    text_snippets = set()
    links = set()
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT result FROM scan_results
                WHERE target = %s AND module = %s
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (watch_id, "watch_tower")
            )
            record = cursor.fetchone()
            if record:
                last_run_data = json.loads(record[0])
                text_snippets = set(last_run_data.get("all_text_snippets", []))
                links = set(last_run_data.get("all_links", []))
                logger.debug(f"Loaded {len(text_snippets)} snippets and {len(links)} links for watch_id {watch_id}")
                
    except Exception as e:
        logger.error(f"Failed to get last scan results from DB for '{watch_id}': {e}")
    finally:
        if conn:
            conn.close()
    return text_snippets, links

def _save_baseline_data(watch_id: str, text_snippets: Set[str], links: Set[str]):
    """
    Saves the current run's text and links to the database as the new baseline.
    """
    report = {
        "all_text_snippets": list(text_snippets),
        "all_links": list(links)
    }
    save_scan_to_db(
        target=watch_id, 
        module="watch_tower", 
        data=report
    )

def monitor_page_for_changes(watch_config: PageMonitorConfig):
    """
    The core function that performs a single page watch.
    """
    watch_id = watch_config.watch_id
    url = watch_config.url
    keywords = [k.lower() for k in watch_config.keywords]
    
    # 1. Get baseline data from the last run
    baseline_text, baseline_links = _get_baseline_data(watch_id)

    # 2. Fetch new data from the live page
    current_text, current_links = _fetch_and_parse_page(url)
    
    if not current_text and not current_links:
        logger.warning(f"No data retrieved for URL: {url}. Skipping watch.")
        return

    # 3. Find the differences
    new_text_snippets = current_text - baseline_text
    new_links = current_links - baseline_links
    
    result = TextDiffResult(watch_id=watch_id, url=url)
    
    # 4. Check new text for keywords
    if new_text_snippets:
        logger.info(f"Found {len(new_text_snippets)} new text snippets on {url}")
        result.status = "changed"
        
        if keywords:
            for snippet in new_text_snippets:
                snippet_lower = snippet.lower()
                for kw in keywords:
                    if kw in snippet_lower:
                        logger.warning(f"Keyword '{kw}' found in new text on {url}: {snippet}")
                        result.new_keyword_findings.append(f"{kw}: {snippet}")

    # 5. Check for new links
    if new_links:
        logger.info(f"Found {len(new_links)} new external links on {url}")
        result.status = "changed"
        result.new_links_found = list(new_links)

    # 6. Dispatch alerts if changes were found
    if result.status == "changed":
        if result.new_keyword_findings:
            alert_manager_instance.dispatch_alert(
                title=f"Keyword Alert: {url}",
                message=(
                    f"New keywords found on monitored page: {url}\n\n" +
                    "\n".join([f"- {finding}" for finding in result.new_keyword_findings])
                ),
                level=AlertLevel.WARNING,
                provenance={"module": "watch_tower", "watch_id": watch_id, "url": url}
            )
        
        if result.new_links_found and watch_config.monitor_for_new_links:
             alert_manager_instance.dispatch_alert(
                title=f"New Links Found: {url}",
                message=(
                    f"New external links found on monitored page: {url}\n\n" +
                    "\n".join([f"- {link}" for link in result.new_links_found])
                ),
                level=AlertLevel.INFO,
                provenance={"module": "watch_tower", "watch_id": watch_id, "url": url}
            )

    # 7. Save the current data as the new baseline
    _save_baseline_data(watch_id, current_text, current_links)
    

def run_all_watch_towers():
    """
    Wrapper function for the scheduler.
    Iterates through all projects and runs the keyword monitor for each page.
    """
    logger.info("DAEMON: Starting scheduled run for OSINT Watch Tower...")
    try:
        project_names = list_projects()
        if not project_names:
            logger.info("DAEMON: No projects found to monitor.")
            return

        for project_name in project_names:
            config = get_project_config_by_name(project_name)
            if not config or not config.pages_to_monitor:
                continue
                
            logger.info(f"DAEMON: Checking {len(config.pages_to_monitor)} watched pages for '{project_name}'...")
            for watch_config in config.pages_to_monitor:
                try:
                    monitor_page_for_changes(watch_config)
                except Exception as e:
                    logger.error(
                        f"DAEMON: Unhandled error while monitoring page '{watch_config.url}': {e}",
                        exc_info=True
                    )
        logger.info("DAEMON: Finished scheduled run for OSINT Watch Tower.")
    except Exception as e:
        logger.error(
            f"DAEMON: Critical error during job startup: {e}",
            exc_info=True
        )

# --- Typer CLI Application ---

watch_tower_app = typer.Typer(help="OSINT Watch Tower for monitoring page text and keywords.")

@watch_tower_app.command("monitor-schedule-add")
def schedule_watch_tower(
    schedule: str = typer.Option(
        "*/30 * * * *", # Every 30 minutes
        "--schedule",
        "-s",
        help="Cron schedule (e.g., '*/30 * * * *' for every 30 minutes)."
    ),
):
    """Schedules the OSINT Watch Tower to run periodically.
    
    This job will iterate through all projects, find their defined
    watched pages, and alert on new text snippets containing keywords.
    """
    try:
        job_id = "global_osint_watch_tower"
        add_job(
            func=run_all_watch_towers,
            trigger="cron",
            cron_schedule=schedule,
            job_id=job_id,
            kwargs={},
        )
        typer.echo(
            f"[bold green]Successfully scheduled Watch Tower job '{job_id}' "
            f"with schedule: '{schedule}'[/bold green]"
        )
        typer.echo("The daemon will now run this check automatically.")
    except Exception as e:
        typer.echo(f"An unexpected error occurred while scheduling: {e}", err=True)
        raise typer.Exit(code=1)

@watch_tower_app.command("run-once")
def run_once(
    project_name: str = typer.Option(
        ..., 
        "--project",
        "-p",
        help="The specific project name to run the monitor for."
    ),
):
    """
    Runs the Watch Tower a single time for all pages in a specific project.
    """
    try:
        config = get_project_config_by_name(project_name)
        if not config:
            console.print(f"[bold red]Error:[/bold red] Project '{project_name}' not found.")
            raise typer.Exit(code=1)
        
        if not config.pages_to_monitor:
            console.print(f"No pages are configured for monitoring in project '{project_name}'.")
            console.print("Use 'chimera project add-watch' to add one.")
            raise typer.Exit()
            
        typer.echo(f"Starting manual Watch Tower run for {len(config.pages_to_monitor)} pages in {project_name}...")
        
        for watch_config in config.pages_to_monitor:
            typer.echo(f"  - Checking: {watch_config.url}")
            monitor_page_for_changes(watch_config)
            
        typer.echo(f"Manual run complete for: {project_name}")
        
    except Exception as e:
        typer.echo(f"An unexpected error occurred during the run: {e}", err=True)
        raise typer.Exit(code=1)