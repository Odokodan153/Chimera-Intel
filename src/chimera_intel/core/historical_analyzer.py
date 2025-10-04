"""
Module for Historical Website Analysis.

Analyzes the differences between two historical snapshots of a website to identify
and summarize changes in content and structure.
"""

import typer
import logging
import httpx
import difflib
from typing import Optional
import asyncio
from bs4 import BeautifulSoup
from .schemas import HistoricalAnalysisResult
from .utils import console
from .ai_core import generate_swot_from_data
from .config_loader import API_KEYS
from .temporal_analyzer import get_historical_snapshots

logger = logging.getLogger(__name__)

historical_app = typer.Typer(
    name="historical-analyzer",
    help="Analyze historical changes to a website.",
)


async def get_snapshot_content(snapshot_url: str) -> str:
    """Fetches the textual content of a given Wayback Machine snapshot."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(snapshot_url, follow_redirects=True)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            return soup.get_text()
    except httpx.HTTPError as e:
        logger.error(f"Failed to fetch snapshot content from {snapshot_url}: {e}")
        return ""


def compare_content(content1: str, content2: str) -> str:
    """Compares two text contents and returns a diff."""
    diff = difflib.unified_diff(
        content1.splitlines(keepends=True),
        content2.splitlines(keepends=True),
        fromfile="older_snapshot",
        tofile="newer_snapshot",
    )
    return "".join(diff)


async def analyze_historical_changes(
    domain: str,
    from_timestamp: Optional[str] = None,
    to_timestamp: Optional[str] = None,
) -> HistoricalAnalysisResult:
    """
    Analyzes the historical changes of a website between two points in time.
    """
    snapshots_result = get_historical_snapshots(domain)
    if snapshots_result.error or not snapshots_result.snapshots:
        return HistoricalAnalysisResult(
            domain=domain,
            error="Could not retrieve historical snapshots for the domain.",
        )
    snapshots = sorted(snapshots_result.snapshots, key=lambda s: s.timestamp)

    if not from_timestamp:
        from_snapshot = snapshots[0]
    else:
        from_snapshot = next(
            (s for s in snapshots if s.timestamp >= from_timestamp), None
        )
    if not to_timestamp:
        to_snapshot = snapshots[-1]
    else:
        to_snapshot = next(
            (s for s in reversed(snapshots) if s.timestamp <= to_timestamp), None
        )
    if (
        not from_snapshot
        or not to_snapshot
        or from_snapshot.timestamp >= to_snapshot.timestamp
    ):
        return HistoricalAnalysisResult(
            domain=domain,
            error="Could not find suitable snapshots for the given timestamps.",
        )
    from_content = await get_snapshot_content(
        f"http://web.archive.org/web/{from_snapshot.timestamp}/{from_snapshot.url}"
    )
    to_content = await get_snapshot_content(
        f"http://web.archive.org/web/{to_snapshot.timestamp}/{to_snapshot.url}"
    )

    if not from_content or not to_content:
        return HistoricalAnalysisResult(
            domain=domain,
            error="Failed to retrieve content from one or both snapshots.",
        )
    diff_output = compare_content(from_content, to_content)

    api_key = API_KEYS.google_api_key
    ai_summary = "AI analysis skipped: GOOGLE_API_KEY not configured."
    if api_key:
        prompt = f"""
        As a web analyst, please analyze the following textual diff of a website's content.
        Summarize the most significant changes, such as new sections, removed content, or major rewording.

        Diff:
        ```diff
        {diff_output}
        ```
        """
        summary_result = generate_swot_from_data(prompt, api_key)
        if summary_result and not summary_result.error:
            ai_summary = summary_result.analysis_text
    return HistoricalAnalysisResult(
        domain=domain,
        from_timestamp=from_snapshot.timestamp,
        to_timestamp=to_snapshot.timestamp,
        diff=diff_output,
        ai_summary=ai_summary,
    )


@historical_app.command("run")
def run_historical_analysis(
    domain: str = typer.Argument(..., help="The domain to analyze."),
    from_timestamp: Optional[str] = typer.Option(
        None,
        "--from",
        help="The start timestamp (YYYYMMDDHHMMSS). Defaults to the earliest snapshot.",
    ),
    to_timestamp: Optional[str] = typer.Option(
        None,
        "--to",
        help="The end timestamp (YYYYMMDDHHMMSS). Defaults to the latest snapshot.",
    ),
):
    """Analyzes the historical changes of a website."""
    console.print(
        f"[bold cyan]Analyzing historical changes for {domain}...[/bold cyan]"
    )
    result = asyncio.run(
        analyze_historical_changes(domain, from_timestamp, to_timestamp)
    )

    if result.error:
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        raise typer.Exit(code=1)
    console.print(
        f"\n[bold green]Comparison between {result.from_timestamp} and {result.to_timestamp}[/bold green]"
    )
    console.print("\n[bold]AI Summary of Changes:[/bold]")
    console.print(result.ai_summary)
