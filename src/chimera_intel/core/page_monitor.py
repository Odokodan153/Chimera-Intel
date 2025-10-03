"""
Website Change Monitoring & Archiving Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import os
import hashlib
from playwright.sync_api import sync_playwright
from PIL import Image
from skimage.metrics import structural_similarity as ssim
import numpy as np
from datetime import datetime
from difflib import SequenceMatcher
from rich.console import Console

from chimera_intel.core.scheduler import add_job
from chimera_intel.core.utils import send_slack_notification, send_teams_notification

console = Console()
BASELINE_DIR = "page_monitor_baselines"


def compare_images(img_path1: str, img_path2: str) -> float:
    """Compares two images and returns a similarity score."""
    img1 = np.array(Image.open(img_path1).convert("L"))
    img2 = np.array(Image.open(img_path2).convert("L"))

    # Ensure images are the same size

    h, w = min(img1.shape[0], img2.shape[0]), min(img1.shape[1], img2.shape[1])
    img1 = img1[:h, :w]
    img2 = img2[:h, :w]

    return ssim(img1, img2, data_range=img2.max() - img2.min())


def compare_text(text1: str, text2: str) -> float:
    """Compares two strings and returns a similarity ratio."""
    return SequenceMatcher(None, text1, text2).ratio()


def run_page_monitor(url: str):
    """
    The core function that runs as a scheduled job. It captures a web page
    and compares it to a stored baseline.
    """
    console.print(f"[{datetime.datetime.now()}] Running Page Monitor for URL: {url}")
    os.makedirs(BASELINE_DIR, exist_ok=True)

    url_hash = hashlib.md5(url.encode()).hexdigest()
    baseline_text_path = os.path.join(BASELINE_DIR, f"{url_hash}_baseline.txt")
    baseline_img_path = os.path.join(BASELINE_DIR, f"{url_hash}_baseline.png")
    current_img_path = os.path.join(BASELINE_DIR, f"{url_hash}_current.png")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, wait_until="networkidle")
            current_text = page.inner_text("body")
            page.screenshot(path=current_img_path, full_page=True)
            browser.close()
        # If baseline exists, compare

        if os.path.exists(baseline_text_path) and os.path.exists(baseline_img_path):
            with open(baseline_text_path, "r", encoding="utf-8") as f:
                baseline_text = f.read()
            text_similarity = compare_text(baseline_text, current_text)
            img_similarity = compare_images(baseline_img_path, current_img_path)

            console.print(f"  - Text Similarity: {text_similarity:.2%}")
            console.print(f"  - Image Similarity: {img_similarity:.2%}")

            # Check if changes exceed thresholds

            if text_similarity < 0.95 or img_similarity < 0.95:
                message = f"🚨 Chimera Intel Alert: Significant change detected on {url}\n- Text Similarity: {text_similarity:.2%}\n- Visual Similarity: {img_similarity:.2%}"
                send_slack_notification(message)
                send_teams_notification(message)
                console.print(
                    f"[bold red]Change detected![/bold red] Updating baseline."
                )
                # Update baseline

                os.rename(current_img_path, baseline_img_path)
                with open(baseline_text_path, "w", encoding="utf-8") as f:
                    f.write(current_text)
            else:
                os.remove(current_img_path)  # Clean up if no change
        else:
            # Create new baseline

            console.print(f"No baseline found for {url}. Creating a new one.")
            os.rename(current_img_path, baseline_img_path)
            with open(baseline_text_path, "w", encoding="utf-8") as f:
                f.write(current_text)
    except Exception as e:
        console.print(
            f"[bold red]An error occurred while monitoring {url}:[/bold red] {e}"
        )


page_monitor_app = typer.Typer(
    name="page-monitor",
    help="Continuous Website Change Monitoring & Archiving",
)


@page_monitor_app.command(
    "add", help="Add a new website monitoring job to the scheduler."
)
def add_page_monitor(
    url: Annotated[
        str,
        typer.Option(
            "--url", "-u", help="The URL to monitor.", prompt="Enter the URL to monitor"
        ),
    ],
    schedule: Annotated[
        str,
        typer.Option(
            "--schedule",
            "-s",
            help="Cron-style schedule (e.g., '0 */6 * * *' for every 6 hours).",
            prompt="Enter cron schedule",
        ),
    ],
):
    """
    Schedules a recurring job to monitor a web page for visual and textual changes.
    """
    job_id = f"page_monitor_{hashlib.md5(url.encode()).hexdigest()}"

    add_job(
        func=run_page_monitor,
        trigger="cron",
        cron_schedule=schedule,
        job_id=job_id,
        kwargs={"url": url},
    )
    console.print(
        f"[bold green]✅ Successfully scheduled page monitor for {url}.[/bold green]"
    )
    console.print(f"   - Job ID: {job_id}")
    console.print(f"   - Schedule: {schedule}")
    console.print(
        "\nEnsure the Chimera daemon is running for the job to execute: [bold]chimera daemon start[/bold]"
    )
