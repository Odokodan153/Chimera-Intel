# src/chimera_intel/core/aia_framework.py


import logging
import json
import asyncio
import re
import uuid
import os
import importlib
import pkgutil
from logging.handlers import RotatingFileHandler
from typing import List, Tuple, Optional, Dict, Any
from datetime import datetime

from .schemas import Plan, Task, SynthesizedReport, AnalysisResult
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .advanced_reasoning_engine import generate_reasoning, decompose_objective

# --- Logger with RotatingFileHandler ---


logger = logging.getLogger(__name__)
if not logger.handlers:
    log_level = os.getenv("AIA_LOG_LEVEL", "INFO").upper()
    logger.setLevel(log_level)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Rotate log file when it reaches 5MB, keep 3 backup files.

    file_handler = RotatingFileHandler(
        "aia.log", maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console handler for user-friendly output

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    # Only show INFO and above on the console

    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)
# --- Dynamic Module Loader ---


def load_available_modules() -> Dict[str, Dict[str, Any]]:
    """Dynamically loads modules from the 'chimera_intel.core.modules' package."""
    modules: Dict[str, Dict[str, Any]] = {}
    ALLOWED_MODULES = {"footprint", "threat_intel", "vulnerability_scanner"}
    try:
        import chimera_intel.core.modules as aia_modules

        for _, name, _ in pkgutil.iter_modules(
            aia_modules.__path__, aia_modules.__name__ + "."
        ):
            module_name = name.split(".")[-1]
            if module_name not in ALLOWED_MODULES:
                continue
            mod = importlib.import_module(name)
            if hasattr(mod, "run"):
                # Basic validation of the 'run' function signature

                if callable(mod.run):
                    modules[module_name] = {
                        "func": mod.run,
                        "is_async": asyncio.iscoroutinefunction(mod.run),
                    }
                else:
                    logger.warning(
                        f"Module {module_name} has a 'run' attribute that is not callable."
                    )
            else:
                logger.warning(f"Module {module_name} does not have a 'run' function.")
    except Exception as e:
        logger.warning(
            f"Dynamic module loading failed: {e}. Falling back to built-ins."
        )
    if not modules:
        # Fallback to ensure core functionality is present if dynamic loading fails

        from .footprint import run_footprint_analysis
        from .threat_intel import get_threat_intel_otx

        modules["footprint"] = {"func": run_footprint_analysis, "is_async": True}
        modules["threat_intel"] = {"func": get_threat_intel_otx, "is_async": False}
    logger.info(f"Loaded {len(modules)} modules: {list(modules.keys())}")
    return modules


# --- AIA Core Logic ---


def create_initial_plans(objective: str) -> List[Plan]:
    """Creates initial plans by decomposing the high-level objective."""
    initial_tasks = decompose_objective(objective)
    if not initial_tasks:
        logger.error("Objective decomposition failed to produce any tasks.")
        return []
    # For simplicity, we'll create one plan with all initial tasks.
    # A more advanced implementation could group tasks into multiple plans.

    return [
        Plan(
            objective=objective,
            tasks=[
                Task(
                    id=str(uuid.uuid4()),
                    module=task["module"],
                    params=task["params"],
                )
                for task in initial_tasks
            ],
        )
    ]


async def execute_plan(
    plan: Plan,
    console: Console,
    available_modules: Dict[str, Dict[str, Any]],
    timeout: int,
) -> Plan:
    """
    Executes pending tasks in parallel, handling both async and sync modules efficiently.
    """
    pending_tasks = [t for t in plan.tasks if t.status == "pending"]
    sem = asyncio.Semaphore(5)

    async def run_task(task: Task) -> Task:
        module_info = available_modules.get(task.module)
        if not module_info:
            task.status = "failed"
            task.result = {"error": f"Module '{task.module}' not found."}
            return task
        task.status = "running"
        try:
            async with sem:
                # The current approach of creating a list of awaitables (coroutines
                # and tasks wrapped in to_thread) and running them in a single
                # gather is already highly efficient for mixed I/O-bound and
                # CPU-bound (sync) tasks. Separating them would add complexity
                # without significant performance gains for this use case.

                if module_info["is_async"]:
                    coro = module_info["func"](**task.params)
                else:
                    coro = asyncio.to_thread(module_info["func"], **task.params)
                task.result = await asyncio.wait_for(coro, timeout=float(timeout))
                task.status = "completed"
        except asyncio.TimeoutError:
            task.status = "failed"
            task.result = {"error": f"TimeoutError: Task execution exceeded {timeout}s"}
        except Exception as e:
            task.status = "failed"
            task.result = {"error": f"{type(e).__name__}: {e}"}
        finally:
            logger.info(f"[{task.status.upper()}] Task {task.id[:8]} ({task.module})")
        return task

    if pending_tasks:
        status = console.status(
            f"Running {len(pending_tasks)} tasks in parallel...", spinner="dots"
        )
        try:
            status.start()
            await asyncio.gather(*[run_task(t) for t in pending_tasks])
        finally:
            status.stop()
    return plan


def synthesize_and_refine(
    plan: Plan, task_execution_counts: Dict[Tuple[str, str], int]
) -> Tuple[SynthesizedReport, Plan]:
    """Synthesizes results and calls the reasoning engine to generate new tasks."""
    report = SynthesizedReport(
        objective=plan.objective,
        summary="Mock summary of completed tasks.",
        hypotheses=[],
        recommendations=[],
        key_findings=[],
        raw_outputs=[],
    )

    completed_results = []
    for task in plan.tasks:
        if task.status == "completed" and task.result:
            try:
                # Attempt to serialize to dict, otherwise cast to string

                data = (
                    task.result.dict()
                    if hasattr(task.result, "dict")
                    else json.loads(json.dumps(task.result, default=str))
                )
            except (TypeError, json.JSONDecodeError):
                data = str(task.result)
            completed_results.append(AnalysisResult(module_name=task.module, data=data))
            report.raw_outputs.append({task.module: data})
    reasoning_output = generate_reasoning(plan.objective, completed_results)
    logger.info(f"Reasoning Summary: {reasoning_output.analytical_summary}")

    # The task_execution_counts dictionary serves as a global guard against
    # recursive tasks from any module, not just 'footprint'. By tracking the
    # execution count of each unique task (module + params), we prevent loops.

    new_tasks_added = 0
    for step in reasoning_output.next_steps:
        # More precise duplicate check

        is_duplicate = any(
            t.module == step["module"] and t.params == step["params"]
            for t in plan.tasks
        )
        if not is_duplicate:
            key = (step["module"], json.dumps(step["params"], sort_keys=True))
            task_execution_counts[key] = task_execution_counts.get(key, 0) + 1
            if task_execution_counts[key] > 2:
                logger.warning(f"Skipping {key} due to repeated execution limit.")
                continue
            plan.tasks.append(
                Task(
                    id=str(uuid.uuid4()),
                    module=step["module"],
                    params=step["params"],
                    status="pending",  # Ensure new tasks are ready to be executed
                )
            )
            new_tasks_added += 1
    if new_tasks_added > 0:
        logger.info(f"New tasks added: {new_tasks_added}")
    report.summary = reasoning_output.analytical_summary or report.summary
    report.hypotheses = reasoning_output.hypotheses
    report.recommendations = reasoning_output.recommendations

    return report, plan


# --- CLI Integration ---


app = typer.Typer(
    name="aia", help="Autonomous Intelligence Agent Framework.", no_args_is_help=True
)


async def _run_autonomous_analysis(
    objective: str, output_file: Optional[str], max_runs: int, timeout: int
):
    console = Console()
    console.print(
        Panel(
            f"[bold yellow]Objective Received:[/] '{objective}'", border_style="yellow"
        )
    )

    if os.path.exists(output_file):
        if not typer.confirm(f"File '{output_file}' already exists. Overwrite?"):
            console.print("[bold red]Aborted.[/]")
            raise typer.Abort()
    available_modules = load_available_modules()
    plans = create_initial_plans(objective)

    if not plans:
        console.print(
            "[bold red]Error: Could not create an initial plan from the objective. Check LLM connectivity and API key.[/]"
        )
        raise typer.Exit(code=1)  # Exit with a non-zero code for automation
    final_reports: List[SynthesizedReport] = []

    for i, plan in enumerate(plans):
        console.print(
            Panel(
                f"[bold]Executing Sub-Plan {i+1}/{len(plans)}:[/] '{plan.objective}'",
                border_style="blue",
            )
        )

        task_execution_counts: Dict[Tuple[str, str], int] = {}
        run_count = 1
        failed_tasks = 0

        while (
            any(task.status == "pending" for task in plan.tasks)
            and run_count <= max_runs
        ):
            console.print(f"\n[bold]  Executing Run #{run_count}...[/]")
            plan = await execute_plan(plan, console, available_modules, timeout)
            console.print("  ✅ Execution complete.")

            failed_tasks = sum(1 for t in plan.tasks if t.status == "failed")
            if failed_tasks:
                console.print(
                    f"[red]⚠ {failed_tasks} task(s) failed during run {run_count}[/]"
                )
            results_table = Table(
                title=f"Run #{run_count} - Task Results",
                show_header=True,
                header_style="bold magenta",
            )
            results_table.add_column("Module", style="cyan", no_wrap=True)
            results_table.add_column("Status", style="green")
            results_table.add_column("Summary", style="white")
            for task in sorted(
                [t for t in plan.tasks if t.status != "pending"], key=lambda t: t.id
            ):
                status_color = "green" if task.status == "completed" else "red"
                summary_text = (
                    str(task.result)[:100] + "..."
                    if len(str(task.result)) > 100
                    else str(task.result)
                )
                results_table.add_row(
                    task.module, f"[{status_color}]{task.status}[/]", summary_text
                )
            console.print(results_table)

            console.print("\n[bold]  Synthesizing & Reasoning for Next Steps...[/]")
            pending_before = len([t for t in plan.tasks if t.status == "pending"])
            report, plan = synthesize_and_refine(plan, task_execution_counts)
            pending_after = len([t for t in plan.tasks if t.status == "pending"])

            if pending_after > pending_before:
                console.print(
                    f"  [yellow]! Reasoning Engine identified {pending_after - pending_before} new lines of inquiry.[/]"
                )
            elif pending_after == 0 and pending_before > 0:
                console.print(
                    "  [green]✅ Reasoning Engine concludes this sub-plan.[/]"
                )
            console.print(
                f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] Iteration {run_count} complete."
            )
            run_count += 1
        final_reports.append(report)
        console.print(
            f"[blue]Executed {len(plan.tasks)} tasks total ({failed_tasks} failed).[/]"
        )
    console.print("\n" + "=" * 50)
    console.print("[bold green]Consolidated Final Report[/]")
    console.print("=" * 50)
    for i, report in enumerate(final_reports):
        console.print(
            Panel(
                f"[bold]Objective:[/] {report.objective}\n[bold]Summary:[/] {report.summary}",
                border_style="green",
            )
        )
    if output_file:
        try:
            full_report_data = [r.model_dump() for r in final_reports]
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(full_report_data, f, indent=2, ensure_ascii=False)
            console.print(f"\n[bold green]✅ Report saved to:[/] {output_file}")
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
    max_runs: int = typer.Option(
        5, "--max-runs", help="Maximum number of iterative reasoning cycles."
    ),
    timeout: int = typer.Option(
        60, "--timeout", help="Timeout for each task in seconds."
    ),
):
    """Takes an objective and autonomously manages the full intelligence cycle."""
    final_output_file = (
        output_file or f"aia_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    try:
        asyncio.run(
            _run_autonomous_analysis(objective, final_output_file, max_runs, timeout)
        )
    except typer.Exit as e:
        # Catch the exit exception to ensure the exit code is propagated

        raise e
    except Exception as e:
        logger.critical(f"An unhandled error occurred: {e}")
        raise typer.Exit(code=1)


# This is required to make the script runnable for testing


if __name__ == "__main__":
    app()
