import typer
from rich.console import Console
from rich.table import Table
from typing import List, Dict, Any, Optional
import logging
from .database import get_all_scans_for_target, get_scan_history
from .schemas import Prediction, ForecastResult, ExpectedEvent
from .project_manager import resolve_target
import joblib  # type: ignore
import numpy as np
import pandas as pd  # type: ignore
from sklearn.model_selection import train_test_split  # type: ignore
from sklearn.ensemble import RandomForestClassifier  # type: ignore
from sklearn.metrics import accuracy_score  # type: ignore
from datetime import datetime
from chimera_intel.core.arg_service import arg_service_instance

logger = logging.getLogger(__name__)
console = Console()

EXPECTED_EVENTS_LIBRARY: List[ExpectedEvent] = [
    ExpectedEvent(
        event_type="Quarterly Financial Report",
        module="business_intel",
        field_to_check="business_intel.financials.companyName",
        expected_frequency_days=95,
    )
]


def check_for_missed_events(
    target: str, historical_data: List[Dict[str, Any]], module: str
) -> List[str]:
    """
    Checks if any expected recurring events have been missed by analyzing scan timestamps.
    """
    missed_events: List[str] = []
    if not historical_data:
        return missed_events
    now = datetime.now()

    for event_def in EXPECTED_EVENTS_LIBRARY:
        if event_def.module == module:
            last_observed_date = None
            for scan in reversed(historical_data):
                scan_data = scan.get("scan_data", {})
                timestamp = scan.get("timestamp")
                if not timestamp:
                    continue
                field_parts = event_def.field_to_check.split(".")
                data = scan_data
                field_found = True
                for part in field_parts:
                    if isinstance(data, dict) and part in data:
                        data = data.get(part)
                    else:
                        field_found = False
                        break
                if field_found and data is not None:
                    last_observed_date = timestamp
                    break
            if last_observed_date:
                if (now - last_observed_date).days > event_def.expected_frequency_days:
                    missed_events.append(
                        f"Expected '{event_def.event_type}' was not observed in the last {event_def.expected_frequency_days} days. Last seen: {last_observed_date.date()}"
                    )
    return missed_events


def get_arg_strategic_signals() -> List[Prediction]:
    """
    Queries the ARG for high-level strategic patterns.
    """
    predictions: List[Prediction] = []
    
    # Use the pre-built pattern from arg_service.py to find collusion signals
    try:
        shared_director_results = arg_service_instance.find_shared_directors()
        if shared_director_results:
            # Get the most significant signal
            signal = shared_director_results[0] 
            pred = Prediction(
                signal="[bold red]ARG Signal: Potential Collusion[/bold red]",
                details=f"Person '{signal['person_name']}' is a director of {signal['companies_directed']} companies, "
                        f"including: {', '.join(signal['companies'])}. This indicates a potential shared controlling interest or market collusion."
            )
            predictions.append(pred)
    except Exception as e:
        logger.warning(f"Failed to run ARG pattern search for forecaster: {e}")
        # Could append a "warning" prediction if needed
    
    # ---
    # TODO: Add more ARG queries here, e.g., for:
    # - Shared Infrastructure: (Company)-[:RESOLVES_TO]->(IPAddress)<-[:RESOLVES_TO]-(Company)
    # - Technology Clustering: (Company)-[:USES_TECH]->(Technology)
    # ---

    return predictions


def run_prediction_rules(
    historical_data: List[Dict[str, Any]], module: str
) -> ForecastResult:
    """
    Applies a set of simple, rule-based heuristics to historical data to find signals.
    """
    predictions: List[Prediction] = []

    if len(historical_data) < 2:
        return ForecastResult(
            predictions=[],
            notes="Not enough historical data to make predictions. Need at least 2 scans.",
        )
    latest_scan = historical_data[-1].get("scan_data", {})
    previous_scan = historical_data[-2].get("scan_data", {})

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
    breach_prediction = predict_breach_likelihood(latest_scan)
    if breach_prediction:
        predictions.append(breach_prediction)
    acquisition_prediction = predict_acquisition_likelihood(latest_scan)
    if acquisition_prediction:
        predictions.append(acquisition_prediction)
    missed_events = check_for_missed_events(
        latest_scan.get("target", ""), historical_data, module
    )

    if not predictions and not missed_events:
        return ForecastResult(
            predictions=[],
            notes="No strong predictive signals or missed events detected based on the current rule set.",
        )
    return ForecastResult(predictions=predictions, missed_events=missed_events)


def train_breach_prediction_model():
    """
    Trains a machine learning model to predict data breaches based on historical scan data.
    """
    console.print("[bold cyan]Starting breach prediction model training...[/bold cyan]")
    with console.status("[bold green]Loading historical scan data...[/bold green]"):
        all_scans = get_scan_history()
        if not all_scans:
            console.print(
                "[bold red]Error:[/bold red] No historical scan data found to train the model."
            )
            raise typer.Exit(code=1)
    with console.status("[bold green]Featurizing data...[/bold green]"):
        records = []
        for scan in all_scans:
            scan_data = scan.get("scan_data", {})
            if not isinstance(scan_data, dict):
                continue
            num_vulns = 0
            vuln_data = scan_data.get("vulnerability_scanner", {})
            if isinstance(vuln_data, dict):
                for host in vuln_data.get("scanned_hosts", []):
                    if isinstance(host, dict):
                        for port in host.get("open_ports", []):
                            if isinstance(port, dict):
                                num_vulns += len(port.get("vulnerabilities", []))
            records.append(
                {
                    "target": scan["target"],
                    "timestamp": scan["timestamp"],
                    "num_breaches": len(
                        scan_data.get("defensive_breaches", {}).get("breaches", [])
                    ),
                    "num_hosts": len(
                        scan_data.get("vulnerability_scanner", {}).get(
                            "scanned_hosts", []
                        )
                    ),
                    "num_vulns": num_vulns,
                }
            )
        if not records:
            console.print(
                "[bold red]Error:[/bold red] No valid records found after featurizing data."
            )
            raise typer.Exit(code=1)
        df = pd.DataFrame(records)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    with console.status("[bold green]Creating labels...[/bold green]"):
        df["breach_occurred"] = (
            df.sort_values(by="timestamp")
            .groupby("target")["num_breaches"]
            .diff()
            .fillna(0)
        )
        df["breach_occurred"] = (df["breach_occurred"] > 0).astype(int)
        df["breach_occurred"] = (
            df.groupby("target")["breach_occurred"].shift(-1).fillna(0)
        )
    with console.status("[bold green]Training model...[/bold green]"):
        features = ["num_hosts", "num_vulns"]
        X = df[features]
        y = df["breach_occurred"]

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        model = RandomForestClassifier(
            n_estimators=100, random_state=42, class_weight="balanced"
        )
        model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    console.print(f"Model accuracy: [bold green]{accuracy:.2f}[/bold green]")

    joblib.dump(model, "breach_model.pkl")
    console.print(
        "[bold green]✅ Model trained and saved to breach_model.pkl[/bold green]"
    )


def predict_breach_likelihood(scan_data: Dict[str, Any]) -> Optional[Prediction]:
    """
    Predicts the likelihood of a data breach based on the company's security posture.
    """
    try:
        model = joblib.load("breach_model.pkl")
    except FileNotFoundError:
        return None
    num_hosts = len(scan_data.get("vulnerability_scanner", {}).get("scanned_hosts", []))
    num_vulns = 0
    vuln_data = scan_data.get("vulnerability_scanner", {})
    if isinstance(vuln_data, dict):
        for host in vuln_data.get("scanned_hosts", []):
            if isinstance(host, dict):
                for port in host.get("open_ports", []):
                    if isinstance(port, dict):
                        num_vulns += len(port.get("vulnerabilities", []))
    features = np.array([num_hosts, num_vulns]).reshape(1, -1)
    prediction = model.predict_proba(features)[0][1]

    if prediction > 0.75:
        return Prediction(
            signal="[bold red]High Likelihood of Data Breach[/bold red]",
            details=f"The model predicts a {prediction:.0%} likelihood of a data breach based on the current security posture.",
        )
    return None


def predict_acquisition_likelihood(scan_data: Dict[str, Any]) -> Optional[Prediction]:
    """
    Predicts the potential for a company to be an acquisition target.
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

    # --- ARG INTEGRATION ---
    # Fetch strategic signals from the global ARG
    try:
        arg_predictions = get_arg_strategic_signals()
        forecast_result.predictions.extend(arg_predictions)
    except Exception as e:
        logger.error(f"Could not fetch ARG strategic signals: {e}")
    # --- END ARG INTEGRATION ---

    if forecast_result.predictions:
        console.print("\n[bold green]📈 Predictive Signals Detected[/bold green]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Signal Type", style="cyan", no_wrap=False)
        table.add_column("Details / Forecast", style="white", no_wrap=False)
        for pred in forecast_result.predictions:
            table.add_row(pred.signal, pred.details)
        console.print(table)
    if forecast_result.missed_events:
        console.print(
            "\n[bold yellow]❗️ OSINT via Negative Space: Missed Events Detected[/bold yellow]"
        )
        for event in forecast_result.missed_events:
            console.print(f"- {event}")
            
    # This check now correctly accounts for ARG-based predictions
    if not forecast_result.predictions and not forecast_result.missed_events:
        logger.info(
            "No predictive signals found for '%s', notes: %s",
            target_name,
            forecast_result.notes,
        )
        console.print(f"[dim]{forecast_result.notes}[/dim]")


@forecast_app.command("train-breach-model")
def train_breach_model_command():
    """
    Trains and saves the breach prediction model.
    """
    train_breach_prediction_model()