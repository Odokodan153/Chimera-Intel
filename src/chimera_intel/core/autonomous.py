"""
Autonomous Operations & Self-Improvement Engine for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
from rich.console import Console
from rich.panel import Panel
import datetime
import psycopg2
import requests
import pandas as pd
from scipy.stats import ks_2samp

from .database import get_db_connection
from .ai_core import generate_swot_from_data
from .config_loader import API_KEYS

console = Console()

autonomous_app = typer.Typer(
    name="autonomous",
    help="Manages the platform's self-improvement and learning capabilities.",
)


def trigger_retraining_pipeline(
    optimization_plan: str, reason: str = "Model performance degradation"
):
    """
    Triggers an automated model retraining pipeline by sending a webhook
    to a CI/CD platform (e.g., Jenkins, GitLab CI, GitHub Actions).
    """
    console.print(
        f"[bold cyan]Triggering automated model retraining pipeline for reason: {reason}...[/bold cyan]"
    )

    # These attributes are now available due to the change in config_loader.py

    webhook_url = API_KEYS.cicd_webhook_url
    auth_token = API_KEYS.cicd_auth_token

    if not webhook_url:
        console.print(
            "[bold red]Error:[/bold red] CICD_WEBHOOK_URL is not set in your .env file."
        )
        return
    headers = {
        "Content-Type": "application/json",
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    payload = {
        "event_type": "chimera_retraining_trigger",
        "client_payload": {"reason": reason, "optimization_plan": optimization_plan},
    }

    try:
        response = requests.post(webhook_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

        console.print(
            "  - [green]Successfully triggered retraining pipeline via webhook.[/green]"
        )
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error triggering retraining pipeline:[/bold red] {e}")
        # Optionally, save the plan to a file as a fallback

        with open("model_optimization_plan_failed.txt", "w") as f:
            f.write(optimization_plan)
        console.print(
            "  - [yellow]Optimization plan saved to model_optimization_plan_failed.txt as a fallback.[/yellow]"
        )


@autonomous_app.command(
    "optimize-models", help="Analyze performance data and trigger model optimization."
)
def optimize_models(
    module: Annotated[
        str,
        typer.Option(
            "--module",
            "-m",
            help="The module whose models to optimize (e.g., 'forecaster').",
        ),
    ] = "forecaster",
    performance_data: Annotated[
        str,
        typer.Option(
            "--performance-data",
            "-d",
            help="The time window of performance data to analyze (e.g., 'last-90-days').",
        ),
    ] = "last-90-days",
    auto_trigger: Annotated[
        bool,
        typer.Option(
            "--auto-trigger",
            "-t",
            help="Automatically trigger the retraining pipeline if an optimization plan is generated.",
        ),
    ] = False,
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
            "[bold red]Error:[/bold red] Only the 'forecaster' module is supported for optimization at this time."
        )
        raise typer.Exit(code=1)
    # Check for AI API key BEFORE calling AI function (Fixes Argument 2 type error)

    ai_api_key = API_KEYS.google_api_key
    if not ai_api_key:
        console.print(
            "[bold red]Error:[/bold red] GOOGLE_API_KEY is not set. Cannot perform AI-powered analysis."
        )
        raise typer.Exit(code=1)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        ninety_days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=90)
        cursor.execute(
            "SELECT scenario, is_correct, outcome FROM forecast_performance WHERE timestamp >= %s",
            (ninety_days_ago,),
        )
        records = cursor.fetchall()
        cursor.close()
        conn.close()

        if not records:
            console.print(
                "[yellow]No performance records found for the last 90 days. Cannot perform optimization.[/yellow]"
            )
            raise typer.Exit()
        performance_summary = "\n".join(
            [
                f"- Scenario: {r[0]}\n  - Prediction Correct: {r[1]}\n  - Outcome: {r[2]}"
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

        # ai_api_key is guaranteed to be a str here

        ai_result = generate_swot_from_data(prompt, ai_api_key)
        if ai_result.error:
            console.print(f"[bold red]AI Error:[/bold red] {ai_result.error}")
            raise typer.Exit(code=1)
        optimization_plan = ai_result.analysis_text

        console.print(
            Panel(
                optimization_plan,
                title="[bold green]Model Optimization Plan[/bold green]",
                border_style="green",
            )
        )

        if auto_trigger:
            trigger_retraining_pipeline(optimization_plan)
        else:
            console.print(
                "\n[bold]Note:[/] To automatically trigger the retraining pipeline, use the --auto-trigger flag."
            )
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during model optimization:[/bold red] {e}"
        )
        raise typer.Exit(code=1)


@autonomous_app.command(
    "analyze-ab-test", help="Analyze A/B test results and suggest a winner."
)
def analyze_ab_test_results(
    auto_deploy: Annotated[
        bool,
        typer.Option(
            "--auto-deploy",
            "-d",
            help="Automatically trigger deployment of the winning model variant.",
        ),
    ] = False,
):
    """
    Analyzes A/B test results from the database and recommends a model to deploy.
    """
    console.print("[bold cyan]Analyzing A/B test results...[/bold cyan]")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT model_variant, accuracy, latency FROM ab_test_results")
        records = cursor.fetchall()
        cursor.close()
        conn.close()

        if not records:
            console.print("[yellow]No A/B test results found in the database.[/yellow]")
            raise typer.Exit()
        # Simple logic to determine the winner: highest accuracy, with latency as a tie-breaker

        winner = max(records, key=lambda x: (x[1], -x[2]))
        winner_variant, winner_accuracy, winner_latency = winner

        console.print(
            f"[bold green]Winning Model Variant:[/bold green] {winner_variant}"
        )
        console.print(f"  - Accuracy: {winner_accuracy:.4f}")
        console.print(f"  - Latency: {winner_latency:.4f} ms")

        if auto_deploy:
            console.print(
                f"\n[bold]Automatically deploying winning variant '{winner_variant}'...[/bold]"
            )
            # In a real scenario, this would call a deployment API or webhook

            console.print(
                "  - [green]Deployment triggered successfully (simulated).[/green]"
            )
        else:
            console.print(
                "\n[bold]Note:[/] To automatically deploy the winning variant, use the --auto-deploy flag."
            )
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during A/B test analysis:[/bold red] {e}"
        )
        raise typer.Exit(code=1)


@autonomous_app.command("detect-drift", help="Detect data drift between two datasets.")
def detect_data_drift(
    baseline_data_path: Annotated[
        str,
        typer.Option(
            "--baseline",
            "-b",
            help="Path to the baseline dataset (CSV format).",
            prompt=True,
        ),
    ],
    new_data_path: Annotated[
        str,
        typer.Option(
            "--new",
            "-n",
            help="Path to the new dataset (CSV format).",
            prompt=True,
        ),
    ],
    auto_trigger: Annotated[
        bool,
        typer.Option(
            "--auto-trigger",
            "-t",
            help="Automatically trigger a retraining pipeline if drift is detected.",
        ),
    ] = False,
):
    """
    Compares two datasets to detect data drift using the Kolmogorov-Smirnov test.
    """
    console.print("[bold cyan]Detecting data drift...[/bold cyan]")
    try:
        baseline_df = pd.read_csv(baseline_data_path)
        new_df = pd.read_csv(new_data_path)

        drift_detected = False
        for column in baseline_df.columns:
            if column in new_df.columns:
                ks_statistic, p_value = ks_2samp(baseline_df[column], new_df[column])
                if p_value < 0.05:  # Significance level
                    console.print(
                        f"  - [bold red]Drift detected in column '{column}'[/bold red] (p-value: {p_value:.4f})"
                    )
                    drift_detected = True
        if not drift_detected:
            console.print(
                "[bold green]No significant data drift detected.[/bold green]"
            )
        elif auto_trigger:
            trigger_retraining_pipeline(
                "Data drift detected in one or more features.", reason="Data Drift"
            )
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during drift detection:[/bold red] {e}"
        )
        raise typer.Exit(code=1)


@autonomous_app.command(
    "backtest", help="Backtest a forecasting model against historical data."
)
def run_backtesting(
    model_name: Annotated[
        str,
        typer.Option(
            "--model",
            "-m",
            help="The name of the model to backtest.",
            prompt=True,
        ),
    ],
):
    """
    Performs backtesting of a forecasting model against historical data.
    """
    console.print(
        f"[bold cyan]Running backtest for model '{model_name}'...[/bold cyan]"
    )
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT scenario, predicted_outcome, actual_outcome FROM historical_forecasts"
        )
        records = cursor.fetchall()
        cursor.close()
        conn.close()

        if not records:
            console.print(
                "[yellow]No historical forecast data found for backtesting.[/yellow]"
            )
            raise typer.Exit()
        correct_predictions = 0
        for _, predicted, actual in records:
            if predicted == actual:
                correct_predictions += 1
        accuracy = (correct_predictions / len(records)) * 100
        console.print("[bold green]Backtesting Complete:[/bold green]")
        console.print(f"  - Total Forecasts: {len(records)}")
        console.print(f"  - Correct Predictions: {correct_predictions}")
        console.print(f"  - Accuracy: {accuracy:.2f}%")
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]An error occurred during backtesting:[/bold red] {e}")
        raise typer.Exit(code=1)
    
@autonomous_app.command(
    "simulate", help="Run a predictive 'what-if' scenario."
)
def simulate_scenario(
    scenario_description: Annotated[
        str,
        typer.Option(
            "--scenario",
            "-s",
            help="The 'what-if' scenario to simulate (e.g., 'If company X launches product Y').",
            prompt=True,
        ),
    ],
):
    """
    Runs a predictive simulation for a given scenario to identify
    potential risks and opportunities.
    """
    console.print(
        f"Running predictive simulation for scenario: '[bold cyan]{scenario_description}[/bold cyan]'"
    )

    ai_api_key = API_KEYS.google_api_key
    if not ai_api_key:
        console.print(
            "[bold red]Error:[/bold red] GOOGLE_API_KEY is not set. Cannot perform AI-powered simulation."
        )
        raise typer.Exit(code=1)

    try:
        prompt = (
            "You are a strategic risk and opportunity analyst. Your task is to analyze a hypothetical scenario and predict the likely outcomes. "
            "Based on the following scenario, generate a report that includes:\n"
            "1. **Most Likely Outcome:** What is the probable result?\n"
            "2. **Potential Risks:** What are the key dangers or negative consequences?\n"
            "3. **Potential Opportunities:** What are the possible upsides or advantages?\n"
            "4. **Recommended Monitoring Points:** What key indicators should we watch to see how this scenario is developing?\n\n"
            f"**Scenario:**\n{scenario_description}"
        )

        ai_result = generate_swot_from_data(prompt, ai_api_key)
        if ai_result.error:
            console.print(f"[bold red]AI Error:[/bold red] {ai_result.error}")
            raise typer.Exit(code=1)
        
        prediction_text = ai_result.analysis_text

        console.print(
            Panel(
                prediction_text,
                title="[bold green]Scenario Simulation Report[/bold green]",
                border_style="green",
            )
        )

    except Exception as e:
        console.print(
            f"[bold red]An error occurred during scenario simulation:[/bold red] {e}"
        )
        raise typer.Exit(code=1)
