"""
Metacognition & Self-Improving AI Core.
This module analyzes the system's performance logs to identify strengths,
weaknesses, and intelligence gaps, generating recommendations for optimization
and new intelligence collection requirements.
"""

import logging
import json
from typing import List, Dict, Any
from .schemas import (
    OperationLog,
    ModulePerformance,
    OptimizationRecommendation,
    IntelligenceGap,
    MetacognitionReport,
)
import typer
from rich.console import Console
from rich.table import Table

logger = logging.getLogger(__name__)

# --- Core Logic ---


def analyze_performance(logs: List[OperationLog]) -> List[ModulePerformance]:
    """Analyzes the success and cost of operations to find the most efficient strategies."""
    module_data: Dict[str, Dict[str, Any]] = {}
    for log in logs:
        if log.module_name not in module_data:
            module_data[log.module_name] = {
                "success_count": 0,
                "total_count": 0,
                "total_cost": 0.0,
            }
        module_data[log.module_name]["total_count"] += 1
        module_data[log.module_name]["total_cost"] += log.resource_cost
        if log.success:
            module_data[log.module_name]["success_count"] += 1
    performance_results = []
    for name, data in module_data.items():
        success_rate = (
            (data["success_count"] / data["total_count"]) * 100
            if data["total_count"] > 0
            else 0
        )
        average_cost = (
            data["total_cost"] / data["total_count"] if data["total_count"] > 0 else 0
        )
        # Efficiency is high success rate for low cost

        efficiency_score = success_rate / (
            average_cost + 1
        )  # +1 to avoid division by zero

        performance_results.append(
            ModulePerformance(
                module_name=name,
                success_rate=success_rate,
                average_cost=average_cost,
                efficiency_score=efficiency_score,
            )
        )
    return sorted(performance_results, key=lambda p: p.efficiency_score, reverse=True)


def generate_optimizations(
    performance: List[ModulePerformance],
) -> List[OptimizationRecommendation]:
    """Generates recommendations based on module performance."""
    # FIX: Added explicit type annotation for the list

    recommendations: List[OptimizationRecommendation] = []
    if not performance:
        return recommendations
    best_module = performance[0]
    worst_module = performance[-1]

    if best_module.efficiency_score > 50:
        recommendations.append(
            OptimizationRecommendation(
                recommendation=f"Prioritize using the '{best_module.module_name}' module for relevant tasks.",
                justification=f"It has the highest efficiency score ({best_module.efficiency_score:.2f}) with a {best_module.success_rate:.2f}% success rate.",
            )
        )
    if worst_module.efficiency_score < 10 and len(performance) > 1:
        recommendations.append(
            OptimizationRecommendation(
                recommendation=f"Deprioritize or re-evaluate the '{worst_module.module_name}' module.",
                justification=f"It has the lowest efficiency score ({worst_module.efficiency_score:.2f}) with a {worst_module.success_rate:.2f}% success rate.",
            )
        )
    return recommendations


def identify_gaps(
    logs: List[OperationLog], required_intel: List[str]
) -> List[IntelligenceGap]:
    """Identifies intelligence gaps and generates collection requirements."""
    covered_tags = set()
    for log in logs:
        for tag in log.intelligence_tags:
            covered_tags.add(tag)
    gaps = []
    for required in required_intel:
        if required not in covered_tags:
            gaps.append(
                IntelligenceGap(
                    gap_description=f"No intelligence found for the required topic: '{required}'.",
                    generated_collection_requirement=f"Task modules (e.g., GEOINT, FININT) to gather data on '{required}'.",
                )
            )
    return gaps


# --- CLI Integration ---


app = typer.Typer(
    name="metacognition",
    help="The Metacognition & Self-Improving AI Core.",
    no_args_is_help=True,
)


@app.command("run-self-analysis")
def run_self_analysis(
    log_file: str = typer.Argument(
        ..., help="Path to the operational log file (JSON)."
    ),
    requirements_file: str = typer.Argument(
        ..., help="Path to the intelligence requirements file (JSON)."
    ),
):
    """Runs a full metacognitive analysis on the system's performance."""
    console = Console()
    try:
        with open(log_file, "r") as f:
            log_data = json.load(f)
        logs = [OperationLog(**log) for log in log_data]

        with open(requirements_file, "r") as f:
            required_intel = json.load(f)["required_intelligence"]
    except Exception as e:
        console.print(f"[bold red]Error loading input files:[/] {e}")
        return
    with console.status(
        "[bold green]Analyzing performance and generating insights...[/]"
    ):
        performance = analyze_performance(logs)
        optimizations = generate_optimizations(performance)
        gaps = identify_gaps(logs, required_intel)
        report = MetacognitionReport(
            performance_analysis=performance, optimizations=optimizations, gaps=gaps
        )
    console.print("[bold green]Metacognitive Analysis Complete[/]")

    # Performance Table

    perf_table = Table(title="Module Performance Analysis")
    perf_table.add_column("Module", style="cyan")
    perf_table.add_column("Success Rate (%)", style="green")
    perf_table.add_column("Avg. Cost", style="yellow")
    perf_table.add_column("Efficiency Score", style="magenta")
    for p in report.performance_analysis:
        perf_table.add_row(
            p.module_name,
            f"{p.success_rate:.2f}",
            f"{p.average_cost:.2f}",
            f"{p.efficiency_score:.2f}",
        )
    console.print(perf_table)

    # Optimizations Table

    opt_table = Table(title="Optimization Recommendations")
    opt_table.add_column("Recommendation", style="cyan")
    opt_table.add_column("Justification", style="magenta")
    for o in report.optimizations:
        opt_table.add_row(o.recommendation, o.justification)
    console.print(opt_table)

    # Gaps Table

    gap_table = Table(title="Intelligence Gaps & New Requirements")
    gap_table.add_column("Gap Description", style="red")
    gap_table.add_column("Generated Collection Requirement", style="yellow")
    for g in report.gaps:
        gap_table.add_row(g.gap_description, g.generated_collection_requirement)
    console.print(gap_table)
