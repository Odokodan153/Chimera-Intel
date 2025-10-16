"""
Module for Temporal Analysis of a target's web presence.

Analyzes historical snapshots of websites to identify key moments of
transformation, rebranding, or strategic shifts.
"""

import typer
import logging
from typing import Optional
from .schemas import ShiftingIdentityResult, TemporalSnapshot
from .utils import save_or_print_results, console, is_valid_domain
from .database import save_scan_to_db
from .http_client import sync_client
from .project_manager import resolve_target
from rich.panel import Panel

logger = logging.getLogger(__name__)


def get_historical_snapshots(domain: str) -> ShiftingIdentityResult:
    """
    Fetches historical snapshots of a domain from the Wayback Machine.

    Args:
        domain (str): The domain to search for historical snapshots.

    Returns:
        ShiftingIdentityResult: A Pydantic model with the search results.
    """
    logger.info(f"Fetching historical snapshots for {domain} from Wayback Machine.")
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=timestamp,statuscode,original&collapse=timestamp:4"

    try:
        response = sync_client.get(url)
        response.raise_for_status()
        data = response.json()

        # The first row is the header, so we skip it

        snapshots = [
            TemporalSnapshot(
                timestamp=row[0],
                status_code=int(row[1]),
                url=row[2],
            )
            for row in data[1:]
        ]

        return ShiftingIdentityResult(
            domain=domain,
            total_snapshots_found=len(snapshots),
            snapshots=snapshots,
        )
    except Exception as e:
        logger.error(f"Failed to get historical snapshots for {domain}: {e}")
        return ShiftingIdentityResult(
            domain=domain,
            total_snapshots_found=0,
            error=f"An API error occurred: {e}",
        )


# --- Typer CLI Application ---


temporal_app = typer.Typer()


@temporal_app.command("snapshots")
def run_snapshot_search(
    domain: Optional[str] = typer.Argument(
        None,
        help="Optional domain to search for. Uses active project if not provided.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Fetches historical web snapshots to analyze a company's "Shifting Identity".
    """
    target_domain = resolve_target(domain, required_assets=["domain"])

    if not is_valid_domain(target_domain):
        logger.warning("Invalid domain format provided: %s", target_domain)
        console.print(
            Panel(
                f"[bold red]Invalid Input:[/] '{target_domain}' is not a valid domain format.",
                title="Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    with console.status(
        f"[bold cyan]Querying web archives for {target_domain}...[/bold cyan]"
    ):
        results_model = get_historical_snapshots(target_domain)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_domain, module="temporal_snapshots", data=results_dict
    )
