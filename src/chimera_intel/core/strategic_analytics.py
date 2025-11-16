"""
Strategic Analytics & KPI Dashboard Module.

This module implements the functionality described in the user's
design notes, providing high-level KPIs by aggregating data from
other intelligence modules (PRICEINT, PRODINT, etc.).

It addresses the "Metrics & KPIs to track" section of the notes.
"""

import typer
import logging
import statistics
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
from chimera_intel.core.utils import console
from chimera_intel.core.pricing_intel import _load_price_history
from chimera_intel.core.database import get_aggregated_data_for_target

app = typer.Typer(
    no_args_is_help=True,
    help="Strategic Intelligence & KPI Reporting. Integrates data from other modules.",
)
logger = logging.getLogger(__name__)


def get_domain_from_url(url: str) -> Optional[str]:
    """Utility to extract netloc from a URL."""
    if not url:
        return None
    try:
        return urlparse(url).netloc
    except Exception:
        return None


@app.command("kpi-report")
def get_kpi_report(
    target_domain: str = typer.Argument(
        ..., help="The competitor domain (e.g., example.com) to report on."
    )
):
    """
    Generates a KPI report for a target based on tracked data.
    
    This report is based on the strategic metrics defined in the
    platform design notes.
    """
    console.print(
        f"[bold cyan]Generating Strategic KPI Report for: {target_domain}[/bold cyan]"
    )

    # --- 1. Coverage ---
    # As per notes: "% of competitor SKUs tracked."
    console.print("\n[bold]1. Coverage (SKU & Data)[/bold]")

    all_history = _load_price_history()
    target_price_entries = [
        entry
        for entry in all_history
        if target_domain == get_domain_from_url(entry.get("url", ""))
    ]

    tracked_skus = set(entry["url"] for entry in target_price_entries)
    coverage_sku_count = len(tracked_skus)

    console.print(
        f"  - [green]Tracked SKUs (from PRICEINT):[/green] {coverage_sku_count}"
    )

    agg_data = get_aggregated_data_for_target(target_domain)
    if agg_data:
        module_count = len(agg_data.get("modules", {}))
        console.print(
            f"  - [green]Tracked Data Modules (from DB):[/green] {module_count}"
        )
    else:
        console.print(
            "  - [yellow]No aggregated scan data found in DB for this target.[/yellow]"
        )

    # --- 2. Freshness ---
    # As per notes: "median latency between public change and detection."
    # We calculate this as the median age of the last-checked data.
    console.print("\n[bold]2. Freshness (Data Latency)[/bold]")
    if not target_price_entries:
        console.print("  - [yellow]No pricing data found to calculate freshness.[/yellow]")
    else:
        now = datetime.now()
        freshness_deltas_sec = []
        for url in tracked_skus:
            product_history = sorted(
                [e for e in target_price_entries if e["url"] == url],
                key=lambda x: x["timestamp"],
            )
            if product_history:
                last_timestamp = datetime.fromisoformat(product_history[-1]["timestamp"])
                delta = now - last_timestamp
                freshness_deltas_sec.append(delta.total_seconds())

        if freshness_deltas_sec:
            median_freshness_sec = statistics.median(freshness_deltas_sec)
            avg_freshness_sec = statistics.mean(freshness_deltas_sec)
            console.print(
                f"  - [green]Median Data Freshness (Pricing):[/green] {median_freshness_sec / 3600:.2f} hours"
            )
            console.print(
                f"  - [green]Average Data Freshness (Pricing):[/green] {avg_freshness_sec / 3600:.2f} hours"
            )
        else:
            console.print("  - [yellow]Could not calculate freshness from pricing data.[/yellow]")

    # --- 3. Other KPIs (from design notes) ---
    console.print("\n[bold]3. Qualitative & Strategic KPIs[/bold]")
    console.print(
        "  - [blue]Signal Precision:[/blue] Requires manual analyst rating of alerts. (Not automated)"
    )
    console.print(
        "  - [blue]Time-to-Insight:[/blue] Primarily a function of scheduler frequency (e.g., cron job interval)."
    )
    console.print(
        "  - [blue]Business Impact:[/blue] Requires correlation with internal revenue/strategy data. (External analysis)"
    )

    # --- 4. Legal & Ethical Notes (from design notes) ---
    console.print("\n[bold]4. Module Governance Notes (Reminders)[/bold]")
    console.print(
        "  - [gray]Ensure data harvesting modules (PRODINT, PRICEINT) respect robots.txt and TOS."
    )
    console.print(
        "  - [gray]Ensure PII (if collected) is handled per GDPR/privacy policies."
    )
    console.print(
        "  - [gray]Ensure provenance and confidence scores are stored for all generated claims."
    )
    console.print(
        "  - [gray]Ensure licensing for paid data (e.g., SimilarWeb) is respected."
    )