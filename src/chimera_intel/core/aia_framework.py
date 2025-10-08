import logging
import json
import asyncio
import re
from typing import List, Tuple, Optional
from .schemas import (
    Plan,
    Task,
    SynthesizedReport,
)
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.spinner import Spinner
from .footprint import run_footprint_analysis
from .vulnerability_scanner import search_vulnerabilities_by_ip
from .threat_intel import get_threat_intel_otx

from .advanced_reasoning_engine import (
    generate_reasoning,
    decompose_objective,
    AnalysisResult,
)

# --- Logger Configuration ---

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --- AIA Core Logic ---


def create_initial_plans(objective: str) -> List[Plan]:
    """
    Decomposes a high-level objective into one or more sub-plans.
    """
    sub_objectives = decompose_objective(objective)
    plans = []

    for sub_obj in sub_objectives:
        plan = Plan(objective=sub_obj, tasks=[])
        # Use regex to find a potential target for this sub-plan

        match = re.search(
            r"(?:of|for|on|in)\s+([a-zA-Z0-9.-]+\.[a-z]{2,})", sub_obj, re.IGNORECASE
        )
        target_entity = match.group(1) if match else None

        if target_entity:
            if (
                "security posture" in sub_obj.lower()
                or "vulnerabilities" in sub_obj.lower()
            ):
                plan.tasks.append(
                    Task(id=1, module="footprint", params={"domain": target_entity})
                )
        if plan.tasks:
            plans.append(plan)
    return plans


async def execute_plan(plan: Plan, console: Console) -> Plan:
    """Executes all pending tasks in a plan using the real, imported modules."""
    available_modules = {
        "footprint": run_footprint_analysis,
        "vulnerability_scanner": search_vulnerabilities_by_ip,
        "threat_intel": get_threat_intel_otx,
    }

    pending_tasks = sorted(
        [t for t in plan.tasks if t.status == "pending"],
        key=lambda t: t.severity,
        reverse=True,
    )

    for task in pending_tasks:
        task.status = "running"
        spinner = Spinner(
            "dots", text=f" Running Task {task.id}: {task.module}({task.params})..."
        )
        with console.status(spinner):
            if task.module in available_modules:
                try:
                    task.result = await available_modules[task.module](**task.params)
                    task.status = "completed"
                except Exception as e:
                    task.status = "failed"
                    task.result = {"error": f"Module execution failed: {e}"}
                    logger.error(f"Task {task.id} ({task.module}) failed: {e}")
            else:
                task.status = "failed"
                task.result = {"error": f"Module '{task.module}' not found."}
    return plan


def synthesize_and_refine(plan: Plan) -> Tuple[SynthesizedReport, Plan]:
    """
    Synthesizes results and uses the Reasoning Engine to generate insights and new tasks.
    """
    report = SynthesizedReport(objective=plan.objective)

    completed_results = [
        AnalysisResult(module_name=task.module, data=task.result)
        for task in plan.tasks
        if task.status == "completed" and task.result
    ]

    # --- DELEGATE COGNITIVE LOGIC TO THE ADVANCED REASONING ENGINE ---

    reasoning_output = generate_reasoning(plan.objective, completed_results)

    # Update the plan with new, dynamically generated tasks

    new_tasks: List[Task] = []
    run_count = len(
        [t for t in plan.tasks if t.status != "pending"]
    )  # Approximation of run count
    for step in reasoning_output.next_steps:
        is_duplicate = any(
            t.module == step["module"] and t.params == step["params"]
            for t in plan.tasks
        )
        if not is_duplicate:
            new_task_id = len(plan.tasks) + len(new_tasks) + 1
            new_tasks.append(
                Task(
                    id=new_task_id,
                    module=step["module"],
                    params=step["params"],
                    severity=run_count + 1,
                )
            )
    plan.tasks.extend(new_tasks)

    # The summary, hypotheses, and recommendations come from the Reasoning Engine

    report.summary = reasoning_output.analytical_summary
    report.hypotheses = reasoning_output.hypotheses
    report.recommendations = reasoning_output.recommendations

    for task in plan.tasks:
        if task.status == "completed" and task.result:
            report.raw_outputs.append(
                {
                    task.module: (
                        task.result.dict()
                        if hasattr(task.result, "dict")
                        else task.result
                    )
                }
            )
            report.key_findings.append(json.dumps(report.raw_outputs[-1], indent=2))
    return report, plan


# --- CLI Integration ---


app = typer.Typer(
    name="aia",
    help="The Autonomous Intelligence Agent (AIA) Framework with Advanced Reasoning.",
    no_args_is_help=True,
)


async def _run_autonomous_analysis(objective: str, output_file: Optional[str]):
    """The async core function for running the autonomous analysis."""
    console = Console()
    console.print(
        Panel(
            f"[bold yellow]High-Level Objective Received:[/] '{objective}'",
            border_style="yellow",
        )
    )

    # 1. Decompose objective into multiple plans if necessary

    plans = create_initial_plans(objective)
    if not plans:
        console.print(
            "[bold red]Error: Could not parse any actionable sub-objectives or targets.[/]"
        )
        return
    final_reports: List[SynthesizedReport] = []

    for i, plan in enumerate(plans):
        console.print(
            Panel(
                f"[bold]Executing Sub-Plan {i+1}/{len(plans)}:[/] '{plan.objective}'",
                border_style="blue",
            )
        )

        MAX_RUNS = 5
        run_count = 1

        while (
            any(task.status == "pending" for task in plan.tasks)
            and run_count <= MAX_RUNS
        ):
            console.print(f"\n[bold]  Executing Run #{run_count}...[/]")
            plan = await execute_plan(plan, console)
            console.print("  ✅ Execution complete.")

            console.print(
                "\n[bold]  Synthesizing Results & Reasoning for Next Steps...[/]"
            )
            report, plan = synthesize_and_refine(plan)

            pending_tasks_count = len([t for t in plan.tasks if t.status == "pending"])
            if pending_tasks_count > 0:
                console.print(
                    f"  [yellow]! Reasoning Engine identified {pending_tasks_count} new lines of inquiry.[/]"
                )
            else:
                console.print(
                    "  [green]✅ Reasoning Engine concludes this sub-plan.[/]"
                )
            run_count += 1
        final_reports.append(report)
    # --- Final Consolidated Report ---

    console.print("\n" + "=" * 50)
    console.print("[bold green]Consolidated Final Report[/]")
    console.print("=" * 50)

    for i, report in enumerate(final_reports):
        console.print(
            Panel(
                f"[bold]Sub-Objective:[/] {report.objective}\n\n"
                f"[bold]Analytical Summary:[/] {report.summary}",
                title=f"Report for Sub-Plan {i+1}",
                border_style="green",
            )
        )
        if report.hypotheses:
            hyp_table = Table(title="Generated Hypotheses")
            hyp_table.add_column("Statement", style="cyan")
            hyp_table.add_column("Confidence", style="magenta")
            for h in report.hypotheses:
                hyp_table.add_row(h.statement, f"{h.confidence:.0%}")
            console.print(hyp_table)
        if report.recommendations:
            rec_table = Table(title="Recommended Actions")
            rec_table.add_column("Action", style="yellow")
            rec_table.add_column("Priority", style="red")
            for r in report.recommendations:
                rec_table.add_row(r.action, r.priority)
            console.print(rec_table)
    if output_file:
        try:
            full_report_data = [r.model_dump() for r in final_reports]
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(full_report_data, f, indent=2)
            console.print(
                f"\n[bold green]✅ Consolidated report successfully saved to:[/] {output_file}"
            )
        except Exception as e:
            console.print(f"\n[bold red]Error saving report:[/] {e}")


@app.command("execute-objective")
def run_autonomous_analysis_cli(
    objective: str = typer.Argument(
        ..., help="The high-level, natural language objective."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="File to save the final JSON report."
    ),
):
    """
    Takes a high-level objective and autonomously manages the full intelligence cycle.
    """
    asyncio.run(_run_autonomous_analysis(objective, output_file))
