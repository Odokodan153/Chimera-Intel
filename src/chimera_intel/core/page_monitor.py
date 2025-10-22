"""
Continuous Web Page Monitoring Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import httpx
from bs4 import BeautifulSoup
import datetime
from hashlib import sha256

from chimera_intel.core.config_loader import CONFIG
from chimera_intel.core.http_client import get_async_http_client
from chimera_intel.core.scheduler import add_job  # Corrected import
from chimera_intel.core.database import save_page_snapshot
from chimera_intel.core.utils import (
    console,
    send_slack_notification,
    send_teams_notification,
)

# Note: 'datetime' should be imported directly or used as 'datetime.datetime'


async def check_for_changes(url: str, job_id: str):
    """
    The core function that runs as a scheduled job. It fetches a page,
    calculates its hash, compares it to the last hash, and records changes.
    """
    console.print(
        f"[{datetime.datetime.now()}] Checking {url} for changes (Job: {job_id})"
    )

    try:
        # Use a client from the context manager
        async with get_async_http_client() as client:
            response = await client.get(url, follow_redirects=True, timeout=20.0)
            response.raise_for_status()

            # Clean content: remove scripts, styles, and extra whitespace before hashing
            soup = BeautifulSoup(response.text, "html.parser")
            for script_or_style in soup(["script", "style"]):
                script_or_style.decompose()
            clean_text = soup.get_text(separator=" ", strip=True)
            current_hash = sha256(clean_text.encode("utf-8")).hexdigest()

            # The logic relies on save_page_snapshot to handle the persistence and comparison.
            # Corrected: Removed the job_id argument
            change_detected, old_hash = save_page_snapshot(
                url=url, current_hash=current_hash, content=response.text
            )

            if change_detected and old_hash:  # Added a check for old_hash
                console.print(
                    f"[bold red]!! Change Detected for {url}[/bold red] - Hash changed from {old_hash[:8]} to {current_hash[:8]}"
                )

                # Send notifications
                message = f"🚨 Chimera Intel Alert: Significant change detected on monitored URL: {url}. Snapshot taken."

                if CONFIG.notifications and CONFIG.notifications.slack_webhook_url:
                    send_slack_notification(
                        CONFIG.notifications.slack_webhook_url, message=message
                    )
                if CONFIG.notifications and CONFIG.notifications.teams_webhook_url:
                    send_teams_notification(
                        CONFIG.notifications.teams_webhook_url,
                        title=f"Page Change Alert: {url}",
                        message=message,
                    )
            else:
                console.print(
                    f"[bold green]No changes detected for {url}.[/bold green]"
                )
    except httpx.RequestError as e:
        console.print(
            f"[bold yellow]Warning:[/bold yellow] Could not reach {url}. Error: {e}"
        )
    except Exception as e:
        console.print(
            f"[bold red]An unexpected error occurred for {url}:[/bold red] {e}"
        )


# Create a Typer app for the page monitoring commands
page_monitor_app = typer.Typer(
    name="page-monitor",
    help="Continuous Web Page Monitoring for change detection.",
)


@page_monitor_app.command(
    "add", help="Add a new web page monitoring job to the scheduler."
)
def add_page_monitor(
    url: Annotated[
        str,
        typer.Option(
            ...,  # <-- FIX: Mark as required
            "--url",
            "-u",
            help="The URL of the web page to monitor for changes.",
        ),
    ],
    schedule: Annotated[
        str,
        typer.Option(
            ...,  # <-- FIX: Mark as required
            "--schedule",
            "-s",
            help="Cron-style schedule for the monitor (e.g., '0 * * * *' for hourly).",
        ),
    ],
):
    """
    Schedules a recurring job to monitor a specific web page for content changes.
    """
    job_id = f"page_monitor_{sha256(url.encode()).hexdigest()[:8]}"

    add_job(
        func=check_for_changes,
        trigger="cron",
        cron_schedule=schedule,
        job_id=job_id,
        kwargs={"url": url, "job_id": job_id},
    )
    console.print(
        "[bold green]✅ Successfully scheduled web page monitor.[/bold green]"
    )
    console.print(f"   - Job ID: {job_id}")
    console.print(f"   - URL: {url}")
    console.print(f"   - Schedule: {schedule}")
    console.print(
        "\nEnsure the Chimera daemon is running for the job to execute: [bold]chimera daemon start[/bold]"
    )
    
    # --- FIX 1: Removed explicit exit ---
    # The function will now implicitly exit with code 0, which the CliRunner expects.


# --- FIX 2: Proper Typer CLI entrypoint ---
if __name__ == "__main__":
    typer.run(page_monitor_app)