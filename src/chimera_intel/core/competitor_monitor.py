"""
Module for Competitor Intellectual Property (IP) & Data Leakage Monitoring.

This module acts as an offensive CI tool by orchestrating other modules
to monitor competitors for data leaks on the dark web, in code repositories,
and on pastebins.
"""

import typer
import logging
import json
from typing import List, Dict, Set, Any
from .database import save_scan_to_db, get_db_connection
from .config_loader import API_KEYS
from .project_manager import list_projects, get_project_config_by_name
from .alert_manager import alert_manager_instance, AlertLevel
from .scheduler import add_job

# Import the core search functions from other modules
from .defensive import search_github_leaks
from .dark_web_monitor import search_pastebins
from .dark_web_osint import search_dark_web

logger = logging.getLogger(__name__)

# --- Main Monitoring Logic ---

def _generate_keywords(competitor_name: str) -> List[str]:
    """Generates a list of search keywords for a competitor."""
    # Simple keyword generation. This could be expanded with project-specific code names.
    name_parts = competitor_name.split()
    keywords = [
        f'"{competitor_name}"',
        f'"{competitor_name}" internal',
        f'"{competitor_name}" confidential',
        f'"{competitor_name}" leak',
    ]
    # Add keywords for project names if they are simple
    if len(name_parts) > 0 and name_parts[0].lower() != "the":
        keywords.append(f'"{name_parts[0]}" database')
        keywords.append(f'"{name_parts[0]}" credentials')

    return keywords

def _get_seen_leak_urls(project_name: str) -> Set[str]:
    """
    Retrieves the set of all leak URLs seen in the last run for this project.
    """
    seen_urls = set()
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT result FROM scan_results
                WHERE project_name = %s AND module = %s
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (project_name, "competitor_monitor")
            )
            record = cursor.fetchone()
            if record:
                last_run_data = json.loads(record[0])
                seen_urls = set(last_run_data.get("all_seen_leak_urls", []))
                logger.info(f"Loaded {len(seen_urls)} seen leak URLs from last run for '{project_name}'.")
                
    except Exception as e:
        logger.error(f"Failed to get last scan results from DB for '{project_name}': {e}")
    finally:
        if conn:
            conn.close()
    return seen_urls

def monitor_competitor_activity(project_name: str):
    """
    Daemon-callable function to monitor competitor activity for a single project.
    """
    logger.info(f"Running competitor leak monitor for project: {project_name}")
    
    config = get_project_config_by_name(project_name)
    if not config or not config.competitors:
        logger.info(f"No competitors configured for project '{project_name}'. Skipping.")
        return

    seen_leak_urls = _get_seen_leak_urls(project_name)
    all_urls_this_run = set(seen_leak_urls) # Start with old URLs
    new_leaks_found: List[Dict[str, Any]] = []

    for competitor in config.competitors:
        logger.debug(f"Monitoring competitor: {competitor}")
        keywords = _generate_keywords(competitor)
        
        # 1. Search GitHub
        try:
            gh_result = search_github_leaks(keywords, org_name=None)
            if gh_result.items:
                for item in gh_result.items:
                    if item.url not in seen_leak_urls:
                        logger.warning(f"New GitHub leak found for '{competitor}': {item.url}")
                        alert_title = f"New Code Leak: {competitor}"
                        alert_msg = (
                            f"Possible source code or config leak found for competitor '{competitor}'.\n"
                            f"Repo: {item.repository}\n"
                            f"URL: {item.url}"
                        )
                        alert_manager_instance.dispatch_alert(
                            title=alert_title,
                            message=alert_msg,
                            level=AlertLevel.WARNING,
                            provenance={"module": "competitor_monitor", "project": project_name, "competitor": competitor}
                        )
                        new_leaks_found.append(item.model_dump())
                        all_urls_this_run.add(item.url)
        except Exception as e:
            logger.error(f"Failed during GitHub search for '{competitor}': {e}")

        # 2. Search Pastebins
        try:
            # We must pass keywords as a single string to search_pastebins
            paste_query = " OR ".join(keywords)
            paste_result = search_pastebins(paste_query)
            if paste_result.leaks_found:
                for leak in paste_result.leaks_found:
                    if leak.url not in seen_leak_urls:
                        logger.warning(f"New Pastebin leak found for '{competitor}': {leak.url}")
                        alert_title = f"New Pastebin Leak: {competitor}"
                        alert_msg = (
                            f"Possible data leak found on {leak.source} for competitor '{competitor}'.\n"
                            f"Match: {leak.matched_keyword}\n"
                            f"Snippet: {leak.content_snippet[:100]}...\n"
                            f"URL: {leak.url}"
                        )
                        alert_manager_instance.dispatch_alert(
                            title=alert_title,
                            message=alert_msg,
                            level=AlertLevel.WARNING,
                            provenance={"module": "competitor_monitor", "project": project_name, "competitor": competitor}
                        )
                        new_leaks_found.append(leak.model_dump())
                        all_urls_this_run.add(leak.url)
        except Exception as e:
            logger.error(f"Failed during Pastebin search for '{competitor}': {e}")

        # 3. Search Dark Web
        try:
            # Use the primary competitor name for the dark web search
            dw_result = search_dark_web(f'"{competitor}"')
            if dw_result.found_results:
                for hit in dw_result.found_results:
                    if hit.url not in seen_leak_urls:
                        logger.warning(f"New Dark Web mention found for '{competitor}': {hit.title}")
                        alert_title = f"New Dark Web Mention: {competitor}"
                        alert_msg = (
                            f"New dark web search result for competitor '{competitor}'.\n"
                            f"Title: {hit.title}\n"
                            f"Snippet: {hit.description[:150]}...\n"
                            f"URL: {hit.url}"
                        )
                        alert_manager_instance.dispatch_alert(
                            title=alert_title,
                            message=alert_msg,
                            level=AlertLevel.CRITICAL, # Dark web is high priority
                            provenance={"module": "competitor_monitor", "project": project_name, "competitor": competitor}
                        )
                        new_leaks_found.append(hit.model_dump())
                        all_urls_this_run.add(hit.url)
        except Exception as e:
            logger.error(f"Failed during Dark Web search for '{competitor}': {e}")

    # 4. Save this run's results to the database for next time
    if new_leaks_found:
        logger.info(f"Found {len(new_leaks_found)} total new leaks for '{project_name}'.")
        report = {
            "new_findings": new_leaks_found,
            "all_seen_leak_urls": list(all_urls_this_run)
        }
        save_scan_to_db(
            target=project_name, 
            module="competitor_monitor", 
            data=report
        )
    else:
        logger.info(f"No new competitor leaks found for project: {project_name}")


def run_all_project_competitor_monitors():
    """
    Wrapper function for the scheduler.
    Iterates through all projects and runs the competitor monitor for each.
    """
    logger.info("DAEMON: Starting scheduled run for competitor leak monitor...")
    try:
        project_names = list_projects()
        if not project_names:
            logger.info("DAEMON: No projects found to monitor.")
            return

        logger.info(f"DAEMON: Found {len(project_names)} projects for competitor monitoring.")
        for project_name in project_names:
            try:
                monitor_competitor_activity(project_name)
            except Exception as e:
                logger.error(
                    f"DAEMON: Unhandled error while monitoring project '{project_name}': {e}",
                    exc_info=True
                )
        logger.info("DAEMON: Finished scheduled run for competitor leak monitor.")
    except Exception as e:
        logger.error(
            f"DAEMON: Critical error during job startup (e.g., DB connection): {e}",
            exc_info=True
        )

# --- Typer CLI Application ---

comp_mon_app = typer.Typer(help="Competitor CI monitoring tools (Dark Web, Code Leaks).")

@comp_mon_app.command("monitor-schedule-add")
def schedule_competitor_monitor(
    schedule: str = typer.Option(
        "0 */6 * * *", # Every 6 hours
        "--schedule",
        "-s",
        help="Cron schedule (e.g., '0 */6 * * *' for every 6 hours)."
    ),
):
    """Schedules the competitor leak monitor to run periodically.
    
    This job will iterate through all projects, find their defined
    competitors, and alert on new leaks found on GitHub, pastebins,
    and dark web search engines.
    """
    try:
        job_id = "global_competitor_leak_monitor"
        add_job(
            func=run_all_project_competitor_monitors,
            trigger="cron",
            cron_schedule=schedule,
            job_id=job_id,
            kwargs={},
        )
        typer.echo(
            f"[bold green]Successfully scheduled competitor leak monitor job '{job_id}' "
            f"with schedule: '{schedule}'[/bold green]"
        )
        typer.echo("The daemon will now run this check automatically.")
    except Exception as e:
        typer.echo(f"An unexpected error occurred while scheduling: {e}", err=True)
        raise typer.Exit(code=1)

@comp_mon_app.command("run-once")
def run_once(
    project_name: str = typer.Option(
        ..., 
        "--project",
        "-p",
        help="The specific project name to run the monitor for."
    ),
):
    """
    Runs the competitor leak monitor a single time for a specific project.
    """
    try:
        typer.echo(f"Starting manual competitor monitor run for project: {project_name}")
        monitor_competitor_activity(project_name)
        typer.echo(f"Manual run complete for: {project_name}")
    except Exception as e:
        typer.echo(f"An unexpected error occurred during the run: {e}", err=True)
        raise typer.Exit(code=1)