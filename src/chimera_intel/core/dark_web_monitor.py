"""
Continuous Dark Web Monitoring Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import httpx
from bs4 import BeautifulSoup
import datetime
import os
from rich.console import Console

from chimera_intel.core.config_loader import CONFIG
from chimera_intel.core.http_client import get_async_http_client
from chimera_intel.core.scheduler import add_job
from chimera_intel.core.utils import send_slack_notification, send_teams_notification

console = Console()

# In a real system, this would be a call to a threat intelligence API or a secure internal service.
# For this example, we'll simulate it with a function that could be easily adapted.


def get_dark_web_targets() -> list[str]:
    """
    Fetches a curated list of dark web targets from a threat intelligence feed.
    This function simulates a real-world scenario where the target list is dynamic.
    """
    # In a production environment, you might fetch this from a URL like:
    # response = httpx.get("https://api.threatintel.example.com/darkweb/targets", headers={"X-API-KEY": "..."})
    # return response.json()['targets']

    # For this example, we'll use a predefined list to simulate the feed.

    simulated_feed = {
        "hacking_forums": [
            "http://breachedu76kdyavc64t2yb57d42j3634d52nk37f37454s67sk2d.onion/",
            "http://xssforumv3isucukbxhdhwz67b2e5kgyg764i7j6xjsb4o5r26g3t4d.onion/",
            "http://exploitivdot74k24i7gla5s2h2l5cbsg5g5oqa2k3gwdw2ei3x5j7d.onion/",
        ],
        "marketplaces": [
            "http://asap4u2532p5c5z3o2m2g7a3z5cbgd253p2532p5c5z3o2m2g7a3z.onion/",
            "http://alphabay522szl32u4ci5e3iokdsyth56ei7rwngr2wm7i3h55555.onion/",
        ],
        "ransomware_leaks": [
            "http://lockbitapt6vx57t3eeqjofwgcglmutr3i353o2lukb2dlj55x7xid.onion/",
            "http://alphvuz262l67j2cjskqg6g2t2y2p5c5z3o2m2g7a3z5cbgd253p.onion/",
            "http://clop3r2d453p2532p5c5z3o2m2g7a3z5cbgd253p2532p5c5z3o.onion/",
        ],
        "paste_sites": [
            "http://dkeypaste4llb3evjd65s5hmk2v3kvwwfzq7syk455r6gtc3a5nsd.onion/",
        ],
    }
    # Flatten the dictionary of lists into a single list of URLs

    return [url for category in simulated_feed.values() for url in category]


async def run_dark_web_monitor(keywords: list[str]):
    """
    The core function that runs as a scheduled job. It scrapes target sites
    for keywords and sends notifications if found.
    """
    console.print(
        f"[{datetime.datetime.now()}] Running Dark Web Monitor for keywords: {keywords}"
    )

    tor_proxy = CONFIG.modules.dark_web.tor_proxy_url
    if not tor_proxy:
        console.print(
            "[bold red]Error:[/bold red] Tor proxy URL is not configured in config.yaml."
        )
        return
    dark_web_targets = get_dark_web_targets()
    console.print(
        f"  - [cyan]Loaded {len(dark_web_targets)} targets from threat intelligence feed.[/cyan]"
    )

    async with get_async_http_client(
        proxies={"http://": tor_proxy, "https://": tor_proxy}
    ) as client:
        for url in dark_web_targets:
            try:
                response = await client.get(url, timeout=30.0)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, "html.parser")
                page_text = soup.get_text().lower()

                for keyword in keywords:
                    if keyword.lower() in page_text:
                        console.print(
                            f"[bold green]Keyword '{keyword}' found at {url}[/bold green]"
                        )

                        # Save the page for analysis

                        if not os.path.exists("dark_web_captures"):
                            os.makedirs("dark_web_captures")
                        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                        filename = (
                            f"dark_web_captures/capture_{keyword}_{timestamp}.html"
                        )
                        with open(filename, "w", encoding="utf-8") as f:
                            f.write(response.text)
                        # Send notifications

                        message = f"🚨 Chimera Intel Alert: Keyword '{keyword}' detected on the dark web at {url}. Page content saved to '{filename}'."
                        send_slack_notification(message)
                        send_teams_notification(message)
            except httpx.RequestError as e:
                console.print(
                    f"[bold yellow]Warning:[/bold yellow] Could not connect to {url}. Error: {e}"
                )
            except Exception as e:
                console.print(
                    f"[bold red]An unexpected error occurred for {url}:[/bold red] {e}"
                )


# Create a Typer app for the dark web monitoring commands


dark_web_monitor_app = typer.Typer(
    name="dark-monitor",
    help="Continuous Dark Web Monitoring (Counter-Intelligence)",
)


@dark_web_monitor_app.command(
    "add", help="Add a new dark web monitoring job to the scheduler."
)
def add_dark_web_monitor(
    keywords: Annotated[
        str,
        typer.Option(
            "--keywords",
            "-k",
            help="Comma-separated list of keywords to monitor (e.g., 'mycompany.com,internal-api').",
            prompt="Enter keywords to monitor",
        ),
    ],
    schedule: Annotated[
        str,
        typer.Option(
            "--schedule",
            "-s",
            help="Cron-style schedule for the monitor (e.g., '0 * * * *' for hourly).",
            prompt="Enter cron schedule",
        ),
    ],
):
    """
    Schedules a recurring job to monitor dark web sites for specific keywords.
    """
    keyword_list = [k.strip() for k in keywords.split(",")]
    job_id = f"dark_web_monitor_{'_'.join(keyword_list)}"

    add_job(
        func=run_dark_web_monitor,
        trigger="cron",
        cron_schedule=schedule,
        job_id=job_id,
        kwargs={"keywords": keyword_list},
    )
    console.print(
        "[bold green]✅ Successfully scheduled dark web monitor.[/bold green]"
    )
    console.print(f"   - Job ID: {job_id}")
    console.print(f"   - Keywords: {keyword_list}")
    console.print(f"   - Schedule: {schedule}")
    console.print(
        "\nEnsure the Chimera daemon is running for the job to execute: [bold]chimera daemon start[/bold]"
    )
