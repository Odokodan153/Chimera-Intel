import typer
import sqlite3
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from .database import DB_FILE

console = Console()

def get_all_scans_for_target(target: str, module: str) -> list[dict]:
    """
    Retrieves all historical scans for a specific target and module.

    Args:
        target (str): The primary target of the scan (e.g., 'google.com').
        module (str): The name of the module to retrieve scans for (e.g., 'business_intel').

    Returns:
        list[dict]: A list of all historical scan data as dictionaries.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT scan_data FROM scans WHERE target = ? AND module = ? ORDER BY timestamp ASC",
            (target, module)
        )
        records = cursor.fetchall()
        conn.close()
        # Parse the JSON string from each record into a dictionary
        return [json.loads(rec[0]) for rec in records]
    except Exception as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not fetch all historical scans: {e}")
        return []

def run_prediction_rules(historical_data: list, module: str) -> list[str]:
    """
    Applies a set of simple, rule-based heuristics to historical data to find signals.

    Args:
        historical_data (list[dict]): A list of scan results, ordered from oldest to newest.
        module (str): The name of the module being analyzed.

    Returns:
        list[str]: A list of strings, where each string is a potential insight or prediction.
    """
    predictions = []
    
    if len(historical_data) < 2:
        return ["Not enough historical data to make predictions. Need at least 2 scans."]

    # --- Rule Set for the 'business_intel' module ---
    if module == "business_intel":
        latest_scan = historical_data[-1]
        previous_scan = historical_data[-2]
        
        # Rule 1: Check for a surge in news articles
        latest_news_count = latest_scan.get("news", {}).get("totalArticles", 0)
        previous_news_count = previous_scan.get("news", {}).get("totalArticles", 0)
        if latest_news_count > previous_news_count * 2 and latest_news_count > 5:
            predictions.append("[bold yellow]High News Volume:[/bold yellow] A significant increase in news coverage detected. This may indicate a major event (product launch, PR crisis, M&A activity).")

        # Rule 2: Check for new patents (simple check if new patents exist in latest scan)
        latest_patents = {p['title'] for p in latest_scan.get("patents", {}).get("patents", [])}
        previous_patents = {p['title'] for p in previous_scan.get("patents", {}).get("patents", [])}
        new_patents = latest_patents - previous_patents
        if new_patents:
            predictions.append(f"[bold green]Innovation Signal:[/bold green] {len(new_patents)} new patent(s) detected, suggesting R&D activity. Example: '{list(new_patents)[0]}'")

    # --- Rule Set for the 'web_analyzer' module ---
    if module == "web_analyzer":
        latest_tech = {t['technology'] for t in latest_scan.get("web_analysis", {}).get("tech_stack", {}).get("results", [])}
        previous_tech = {t['technology'] for t in previous_scan.get("web_analysis", {}).get("tech_stack", {}).get("results", [])}
        
        # Rule 3: Check for newly added marketing technology
        added_tech = latest_tech - previous_tech
        marketing_tech_keywords = ["HubSpot", "Marketo", "Salesforce", "Analytics", "CRM"]
        new_marketing_tech = [t for t in added_tech if any(keyword in t for keyword in marketing_tech_keywords)]
        if new_marketing_tech:
            predictions.append(f"[bold green]Marketing Expansion Signal:[/bold green] New marketing-related technology detected ({', '.join(new_marketing_tech)}). This could indicate a new marketing campaign or strategy.")

    if not predictions:
        predictions.append("No strong predictive signals detected based on the current rule set.")
        
    return predictions


# --- Typer CLI Application ---

forecast_app = typer.Typer()

@forecast_app.command("run")
def run_forecast_analysis(
    target: str = typer.Argument(..., help="The target to analyze for future signals."),
    module: str = typer.Argument(..., help="The scan module to analyze (e.g., 'business_intel', 'web_analyzer').")
):
    """
    Analyzes historical data to forecast potential future events.
    """
    console.print(Panel(f"[bold green]Forecasting Potential Events For:[/] {target} (Module: {module})", title="Chimera Intel | Predictive Analysis", border_style="green"))

    # Step 1: Get all historical data for the target
    history = get_all_scans_for_target(target, module)

    # Step 2: Run the data through our prediction rules
    predictions = run_prediction_rules(history, module)
    
    # Step 3: Display the results in a clean table
    table = Table(title="Predictive Signals Detected")
    table.add_column("Insight / Forecast", style="cyan", no_wrap=False)
    
    for pred in predictions:
        table.add_row(pred)
        
    console.print(table)