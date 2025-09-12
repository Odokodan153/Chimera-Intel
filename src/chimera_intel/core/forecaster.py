import typer
import sqlite3
import json
from rich.console import Console
from rich.table import Table
from typing import List, Dict, Any, Optional
import logging
from .database import DB_FILE
from .schemas import Prediction, ForecastResult
from .project_manager import resolve_target
import joblib
import numpy as np

# Get a logger instance for this specific file

logger = logging.getLogger(__name__)

# We still need the console for rich table output

console = Console()


def get_all_scans_for_target(target: str, module: str) -> List[Dict[str, Any]]:
    """
    Retrieves all historical scans for a specific target and module.

    Args:
        target (str): The primary target of the scan (e.g., 'google.com').
        module (str): The name of the module to retrieve scans for (e.g., 'business_intel').

    Returns:
        List[Dict[str, Any]]: A list of all historical scan data as dictionaries, ordered by date.
    """
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10.0)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT scan_data FROM scans WHERE target = ? AND module = ? ORDER BY timestamp ASC",
            (target, module),
        )
        records = cursor.fetchall()
        conn.close()
        return [json.loads(rec[0]) for rec in records]
    except sqlite3.Error as e:
        logger.error("Database error fetching all scans for '%s': %s", target, e)
        return []
    except Exception as e:
        logger.critical("Unexpected error fetching all scans for '%s': %s", target, e)
        return []


def run_prediction_rules(
    historical_data: List[Dict[str, Any]], module: str
) -> ForecastResult:
    """
    Applies a set of simple, rule-based heuristics to historical data to find signals.

    This function compares the last two scans to identify significant changes that could
    be predictive of future events.

    Args:
        historical_data (list[dict]): A list of scan results, ordered from oldest to newest.
        module (str): The name of the module being analyzed.

    Returns:
        ForecastResult: A Pydantic model containing a list of predictions or notes.
    """
    predictions: List[Prediction] = []

    if len(historical_data) < 2:
        return ForecastResult(
            predictions=[],
            notes="Not enough historical data to make predictions. Need at least 2 scans.",
        )
    latest_scan = historical_data[-1]
    previous_scan = historical_data[-2]

    # --- Rule Set for the 'business_intel' module ---

    if module == "business_intel":
        latest_news_count = (
            latest_scan.get("business_intel", {})
            .get("news", {})
            .get("totalArticles", 0)
        )
        previous_news_count = (
            previous_scan.get("business_intel", {})
            .get("news", {})
            .get("totalArticles", 0)
        )
        if latest_news_count > previous_news_count * 2 and latest_news_count > 5:
            predictions.append(
                Prediction(
                    signal="[bold yellow]High News Volume[/bold yellow]",
                    details="A significant increase in news coverage detected. This may indicate a major event (product launch, PR crisis, M&A activity).",
                )
            )
        latest_patents = {
            p["title"]
            for p in latest_scan.get("business_intel", {})
            .get("patents", {})
            .get("patents", [])
        }
        previous_patents = {
            p["title"]
            for p in previous_scan.get("business_intel", {})
            .get("patents", {})
            .get("patents", [])
        }
        new_patents = latest_patents - previous_patents
        if new_patents:
            predictions.append(
                Prediction(
                    signal="[bold green]Innovation Signal[/bold green]",
                    details=f"{len(new_patents)} new patent(s) detected, suggesting R&D activity. Example: '{list(new_patents)[0]}'",
                )
            )
    # --- Rule Set for the 'web_analyzer' module ---

    if module == "web_analyzer":
        latest_tech = {
            t["technology"]
            for t in latest_scan.get("web_analysis", {})
            .get("tech_stack", {})
            .get("results", [])
        }
        previous_tech = {
            t["technology"]
            for t in previous_scan.get("web_analysis", {})
            .get("tech_stack", {})
            .get("results", [])
        }

        added_tech = latest_tech - previous_tech
        marketing_tech_keywords = [
            "HubSpot",
            "Marketo",
            "Salesforce",
            "Analytics",
            "CRM",
        ]
        new_marketing_tech = [
            t
            for t in added_tech
            if any(keyword in t for keyword in marketing_tech_keywords)
        ]
        if new_marketing_tech:
            predictions.append(
                Prediction(
                    signal="[bold green]Marketing Expansion Signal[/bold green]",
                    details=f"New marketing-related technology detected ({', '.join(new_marketing_tech)}). This could indicate a new marketing campaign or strategy.",
                )
            )
    # --- Machine Learning Predictions ---

    breach_prediction = predict_breach_likelihood(latest_scan)
    if breach_prediction:
        predictions.append(breach_prediction)
    acquisition_prediction = predict_acquisition_likelihood(latest_scan)
    if acquisition_prediction:
        predictions.append(acquisition_prediction)
    if not predictions:
        return ForecastResult(
            predictions=[],
            notes="No strong predictive signals detected based on the current rule set.",
        )
    return ForecastResult(predictions=predictions)


def train_breach_prediction_model():
    """
    This function is a placeholder for training a breach prediction model.
    It would load historical data from the database, featurize it, and train a model.
    The trained model would then be saved to a file (e.g., 'breach_model.pkl').
    """
    # This is a placeholder. You would need to implement the following steps:
    # 1. Load historical data from the database (all scans).
    # 2. For each company, determine if a breach occurred after a given scan.
    # 3. Featurize the scan data (e.g., number of vulnerabilities, open ports, etc.).
    # 4. Train a classifier (e.g., Logistic Regression, Random Forest) on the data.
    # 5. Save the trained model to a file using joblib.

    pass


def predict_breach_likelihood(scan_data: Dict[str, Any]) -> Optional[Prediction]:
    """
    Predicts the likelihood of a data breach based on the company's security posture.

    Args:
        scan_data (Dict[str, Any]): The latest scan data for the target.

    Returns:
        Optional[Prediction]: A prediction if the model is available, otherwise None.
    """
    try:
        model = joblib.load("breach_model.pkl")
    except FileNotFoundError:
        return None  # Model not trained yet
    # Featurize the input data in the same way as the training data
    # This is a simplified example. You would need to create a more robust
    # feature extraction function.

    features = np.array(
        [
            len(
                scan_data.get("defensive_breaches", {}).get("breaches", [])
            ),  # Existing breaches
            len(
                scan_data.get("vulnerability_scanner", {}).get("scanned_hosts", [])
            ),  # Number of hosts
        ]
    ).reshape(1, -1)

    prediction = model.predict_proba(features)[0][1]  # Probability of breach

    if prediction > 0.75:
        return Prediction(
            signal="[bold red]High Likelihood of Data Breach[/bold red]",
            details=f"The model predicts a {prediction:.0%} likelihood of a data breach based on the current security posture.",
        )
    return None


def predict_acquisition_likelihood(scan_data: Dict[str, Any]) -> Optional[Prediction]:
    """
    Predicts the potential for a company to be an acquisition target.

    Args:
        scan_data (Dict[str, Any]): The latest scan data for the target.

    Returns:
        Optional[Prediction]: A prediction if the conditions are met, otherwise None.
    """
    financials = scan_data.get("business_intel", {}).get("financials", {})
    news = scan_data.get("business_intel", {}).get("news", {})

    pe_ratio = financials.get("trailingPE")
    news_volume = news.get("totalArticles")

    if pe_ratio and news_volume and pe_ratio < 15 and news_volume > 10:
        return Prediction(
            signal="[bold yellow]Potential Acquisition Target[/bold yellow]",
            details="Low P/E ratio and high news volume may indicate that the company is an attractive acquisition target.",
        )
    return None


# --- Typer CLI Application ---


forecast_app = typer.Typer()


@forecast_app.command("run")
def run_forecast_analysis(
    module: str = typer.Argument(
        ..., help="The scan module to analyze (e.g., 'business_intel', 'web_analyzer')."
    ),
    target: Optional[str] = typer.Argument(
        None, help="The target to analyze. Uses active project if not provided."
    ),
):
    """
    Analyzes historical data to forecast potential future events.
    """
    target_name = resolve_target(target, required_assets=["domain"])

    logger.info(
        "Starting forecast analysis for target '%s' in module '%s'", target_name, module
    )

    history = get_all_scans_for_target(target_name, module)
    forecast_result = run_prediction_rules(history, module)

    table = Table(title="Predictive Signals Detected")
    table.add_column("Signal Type", style="cyan", no_wrap=False)
    table.add_column("Details / Forecast", style="white", no_wrap=False)

    if forecast_result.predictions:
        for pred in forecast_result.predictions:
            table.add_row(pred.signal, pred.details)
    elif forecast_result.notes:
        logger.info(
            "No predictive signals found for '%s', notes: %s",
            target_name,
            forecast_result.notes,
        )
        table.add_row("Info", forecast_result.notes)
    console.print(table)
