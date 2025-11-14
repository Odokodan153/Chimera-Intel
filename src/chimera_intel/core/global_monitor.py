"""
Global Blacklist & Keyword Monitoring Module for Chimera Intel.

Schedules jobs to search for keywords (e.g., sanctioned entities,
VIPs) and alerts on new findings.
"""

import typer
from typing_extensions import Annotated
from datetime import datetime
from hashlib import sha256
import logging
import json
from chimera_intel.core.config_loader import CONFIG
from chimera_intel.core.scheduler import add_job
from chimera_intel.core.database import save_page_snapshot, get_latest_snapshot_hash
from chimera_intel.core.utils import (
    console,
    send_slack_notification
)
from chimera_intel.core.google_search import search_google

logger = logging.getLogger(__name__)

async def check_for_keyword_mentions(job_id: str, keyword: str, target: str):
    """
    The core job. Searches Google for a keyword and compares
    the result set to the last known set.
    """
    logger.info(f"Checking for new mentions of '{keyword}' (Job: {job_id})")
    console.print(
        f"[{datetime.datetime.now()}] Checking '{keyword}' (Job: {job_id})"
    )
    
    try:
        # 1. Run the search
        # We add the target to scope the search, e.g., "John Doe" + "sanctions"
        query = f'"{keyword}" AND "{target}"'
        search_results = await search_google(query, num_results=10)
        
        if not search_results:
            logger.info(f"No results found for query: {query}")
            return

        # 2. Create a stable hash of the current results
        # We sort by URL to ensure the hash is consistent
        sorted_results = sorted(search_results, key=lambda x: x.get('url'))
        results_string = json.dumps(sorted_results)
        current_hash = sha256(results_string.encode("utf-8")).hexdigest()

        # 3. Compare with the last known hash
        # We can re-use the 'page_snapshots' table. The 'url' will just be the job_id.
        change_detected, old_hash = save_page_snapshot(
            url=job_id, # Use job_id as the unique key
            current_hash=current_hash, 
            content=results_string # Store the full JSON result set
        )

        if change_detected and old_hash:
            console.print(
                f"[bold red]!! New Mentions Detected for '{keyword}'[/bold red] - Hash {old_hash[:8]} -> {current_hash[:8]}"
            )
            
            # Find the new URL
            try:
                old_results = json.loads(get_latest_snapshot_hash(job_id, old_hash).content)
                old_urls = {r.get('url') for r in old_results}
                new_urls = {r.get('url') for r in sorted_results}
                diff_urls = new_urls.difference(old_urls)
                new_mention_url = list(diff_urls)[0] if diff_urls else "N/A"
            except Exception:
                new_mention_url = "Error parsing diff"

            message = (
                f"🚨 Chimera Intel Alert: New mention detected for monitored keyword: '{keyword}' "
                f"related to target '{target}'.\n"
                f"New URL: {new_mention_url}"
            )

            if CONFIG.notifications and CONFIG.notifications.slack_webhook_url:
                send_slack_notification(
                    CONFIG.notifications.slack_webhook_url, message=message
                )
        else:
            console.print(
                f"[bold green]No new mentions detected for '{keyword}'.[/bold green]"
            )
            
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred for '{keyword}':[/bold red] {e}")
        logger.error(f"Unexpected error checking '{keyword}'", exc_info=e)


# --- CLI ---
global_monitor_app = typer.Typer(
    help="Continuous monitoring for keywords (sanctions, VIPs, etc.)."
)

@global_monitor_app.command(help="Add a new keyword monitoring job to the scheduler.")
def add(
    keyword: Annotated[
        str,
        typer.Option(
            "--keyword",
            "-k",
            help="The keyword or entity name to monitor (e.g., 'John Doe', 'OFAC').",
        ),
    ],
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help="The associated target/project to scope the search (e.g., 'MyCompany').",
        ),
    ],
    schedule: Annotated[
        str,
        typer.Option(
            "--schedule",
            "-s",
            help="Cron-style schedule (e.g., '0 */6 * * *' for every 6 hours).",
        ),
    ],
):
    """
    Schedules a recurring job to search for a keyword.
    """
    # Create a unique job ID based on the keyword and target
    job_id_str = f"global_monitor:{keyword}:{target}"
    job_id = f"gmon_{sha256(job_id_str.encode()).hexdigest()[:10]}"

    add_job(
        func=check_for_keyword_mentions,
        trigger="cron",
        cron_schedule=schedule,
        job_id=job_id,
        kwargs={"job_id": job_id, "keyword": keyword, "target": target},
    )
    console.print(
        "[bold green]✅ Successfully scheduled keyword monitor.[/bold green]"
    )
    console.print(f"   - Job ID: {job_id}")
    console.print(f"   - Keyword: {keyword}")
    console.print(f"   - Target: {target}")
    console.print(f"   - Schedule: {schedule}")
    console.print(
        "\nEnsure the Chimera daemon is running for the job to execute: [bold]chimera daemon start[/bold]"
    )