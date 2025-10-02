"""
Module for Weak Signal Amplification (WSA).

Applies evidence theory (Dempster-Shafer) to combine multiple low-confidence
OSINT signals into a single, higher-confidence assessment of a potential event.
"""

import typer
import logging
from typing import List, Dict, Optional
from collections import defaultdict
from .schemas import AmplifiedEventResult, WeakSignal
from .utils import save_or_print_results, console
from .database import get_aggregated_data_for_target, save_scan_to_db
from .project_manager import resolve_target
from rich.table import Table

logger = logging.getLogger(__name__)


def generate_weak_signals(aggregated_data: Dict) -> List[WeakSignal]:
    """
    Scans aggregated data to generate a list of weak signals with belief scores.
    """
    signals: List[WeakSignal] = []
    modules = aggregated_data.get("modules", {})

    # Signal Hypothesis: "Potential Merger or Acquisition"
    # Rule 1: High news volume

    if modules.get("business_intel", {}).get("news", {}).get("totalArticles", 0) > 20:
        signals.append(
            WeakSignal(
                source_module="business_intel",
                signal_type="MergerOrAcquisition",
                description="Unusually high news volume detected.",
                belief=0.3,
            )
        )
    # Rule 2: Low P/E Ratio

    if (
        modules.get("business_intel", {}).get("financials", {}).get("trailingPE", 100)
        < 15
    ):
        signals.append(
            WeakSignal(
                source_module="business_intel",
                signal_type="MergerOrAcquisition",
                description="Low Price-to-Earnings (P/E) ratio, suggesting undervaluation.",
                belief=0.4,
            )
        )
    # Rule 3: Hiring for "Integration" roles

    job_postings = modules.get("job_postings", {}).get("job_postings", [])
    if any("integration manager" in job.lower() for job in job_postings):
        signals.append(
            WeakSignal(
                source_module="signal_analyzer",
                signal_type="MergerOrAcquisition",
                description="Hiring for roles related to post-merger integration.",
                belief=0.6,
            )
        )
    return signals


def amplify_signals_with_dempster_shafer(
    signals: List[WeakSignal],
) -> List[AmplifiedEventResult]:
    """
    Applies the Dempster-Shafer combination rule to a list of weak signals.
    """
    if not signals:
        return []
    # Group signals by hypothesis (signal_type)

    signals_by_type: Dict[str, List[WeakSignal]] = defaultdict(list)
    for signal in signals:
        signals_by_type[signal.signal_type].append(signal)
    amplified_results: List[AmplifiedEventResult] = []

    for signal_type, signal_group in signals_by_type.items():
        if len(signal_group) < 2:
            continue
        # Dempster's rule of combination for two signals: m1 ⊕ m2
        # m3(A) = (m1(A)m2(A) + m1(A)m2(Θ) + m1(Θ)m2(A)) / (1 - K)
        # where K = m1(A)m2(B) for disjoint A, B
        # Simplified for a single hypothesis A: belief(A) + belief(B) - belief(A)*belief(B)

        combined_belief = signal_group[0].belief
        for i in range(1, len(signal_group)):
            combined_belief = (
                combined_belief
                + signal_group[i].belief
                - (combined_belief * signal_group[i].belief)
            )
        summary = (
            f"The initial evidence, with a belief of {signal_group[0].belief:.0%}, was amplified by "
            f"{len(signal_group) - 1} other weak signal(s), resulting in a combined confidence "
            f"of {combined_belief:.0%} for the hypothesis '{signal_type}'."
        )

        amplified_results.append(
            AmplifiedEventResult(
                event_hypothesis=signal_type,
                combined_belief=combined_belief,
                contributing_signals=signal_group,
                summary=summary,
            )
        )
    return amplified_results


# --- Typer CLI Application ---


wsa_app = typer.Typer()


@wsa_app.command("run")
def run_wsa_analysis(
    target: Optional[str] = typer.Argument(
        None, help="The target to analyze. Uses active project."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Amplifies weak signals from various scans using evidence theory.
    """
    target_name = resolve_target(target, required_assets=["company_name", "domain"])

    with console.status(
        f"[bold cyan]Analyzing weak signals for {target_name}...[/bold cyan]"
    ):
        aggregated_data = get_aggregated_data_for_target(target_name)
        if not aggregated_data:
            console.print(
                f"[bold red]Error:[/bold red] No historical data for {target_name}."
            )
            raise typer.Exit(code=1)
        weak_signals = generate_weak_signals(aggregated_data)
        amplified_events = amplify_signals_with_dempster_shafer(weak_signals)
    if not amplified_events:
        console.print(
            "[bold yellow]No combination of weak signals met the threshold for amplification.[/bold yellow]"
        )
        raise typer.Exit()
    console.print(
        f"\n[bold green]🔥 Amplified Intelligence Events for {target_name}[/bold green]"
    )
    for event in amplified_events:
        console.print(
            f"\n[bold]Hypothesis:[/bold] [cyan]{event.event_hypothesis}[/cyan]"
        )
        console.print(
            f"[bold]Combined Belief:[/bold] [yellow]{event.combined_belief:.1%}[/yellow]"
        )
        console.print(f"[bold]Summary:[/bold] {event.summary}")

        table = Table(title="Contributing Weak Signals")
        table.add_column("Source Module", style="magenta")
        table.add_column("Description")
        table.add_column("Initial Belief", style="green")

        for signal in event.contributing_signals:
            table.add_row(
                signal.source_module, signal.description, f"{signal.belief:.0%}"
            )
        console.print(table)
    if output_file:
        # For now, we save the first amplified event if multiple are found

        results_dict = amplified_events[0].model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        save_scan_to_db(target=target_name, module="wsa_analysis", data=results_dict)
