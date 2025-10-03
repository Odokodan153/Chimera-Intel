"""
Autonomous Operations & Self-Improvement Engine for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
from rich.console import Console
from rich.panel import Panel
import datetime

from .database import get_db
from .schemas import ForecastPerformance
from .ai_core import perform_generative_task

console = Console()

autonomous_app = typer.Typer(
    name="autonomous",
    help="Manages the platform's self-improvement and learning capabilities.",
)


@autonomous_app.command(
    "optimize-models", help="Analyze performance data and simulate model optimization."
)
def optimize_models(
    module: Annotated[
        str,
        typer.Option(
            "--module",
            "-m",
            help="The module whose models to optimize (e.g., 'forecaster').",
            prompt=True,
        ),
    ],
    performance_data: Annotated[
        str,
        typer.Option(
            "--performance-data",
            "-d",
            help="The time window of performance data to analyze (e.g., 'last-90-days').",
        ),
    ] = "last-90-days",
):
    """
    Creates a feedback loop where the results of past operations are used to
    automatically refine the platform's internal models.
    """
    console.print(
        f"Initiating self-optimization for the '[bold cyan]{module}[/bold cyan]' module..."
    )

    if module.lower() != "forecaster":
        console.print(
            f"[bold red]Error:[/bold red] Only the 'forecaster' module is supported for optimization at this time."
        )
        raise typer.Exit(code=1)
    try:
        db = next(get_db())
        # This is a simplified query; a real implementation would parse the time window

        ninety_days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=90)
        records = (
            db.query(ForecastPerformance)
            .filter(ForecastPerformance.timestamp >= ninety_days_ago)
            .all()
        )

        if not records:
            console.print(
                f"[yellow]No performance records found for the last 90 days. Cannot perform optimization.[/yellow]"
            )
            raise typer.Exit()
        # Format the performance data for the AI

        performance_summary = "\n".join(
            [
                f"- Scenario: {r.scenario}\n  - Prediction Correct: {r.is_correct}\n  - Outcome: {r.outcome}"
                for r in records
            ]
        )

        prompt = (
            "You are a Machine Learning Operations (MLOps) specialist. Your task is to analyze the performance of a predictive forecasting model and suggest optimizations. "
            "Based on the following performance data (a list of scenarios, whether the prediction was correct, and the actual outcome), generate a report that includes:\n"
            "1. A summary of the model's overall accuracy and any biases you detect.\n"
            "2. Specific hypotheses for why the model failed on incorrect predictions.\n"
            "3. A recommended action plan for retraining, such as adjusting model parameters, adding new data sources, or refining the analytical prompts.\n\n"
            f"**Performance Data:**\n{performance_summary}"
        )

        optimization_plan = perform_generative_task(prompt)

        console.print(
            Panel(
                optimization_plan,
                title="[bold green]Model Optimization Plan[/bold green]",
                border_style="green",
            )
        )
        console.print(
            "\n[bold]Note:[/] This is a simulation. In a full implementation, these steps would be used to trigger an automated model retraining pipeline."
        )
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during model optimization:[/bold red] {e}"
        )
        raise typer.Exit(code=1)
