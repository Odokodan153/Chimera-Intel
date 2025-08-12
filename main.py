import typer
from modules.footprint import footprint_app
from modules.web_analyzer import web_app
from modules.business_intel import business_app
from modules.defensive import defensive_app
from modules.ai_core import ai_app
from modules.database import initialize_database
from modules.differ import diff_app
from modules.forecaster import forecast_app
from modules.strategist import strategy_app
from modules.signal_analyzer import signal_app # <-- NEW IMPORT

# Initialize the database and table if they don't exist
initialize_database()

# Main Chimera Intel CLI Application
app = typer.Typer(
    name="Chimera Intel",
    help="A modular OSINT platform powered by an AI analysis core.",
    add_completion=False
)

# --- Offensive Intelligence Command Group ---
scan_app = typer.Typer(help="Run offensive intelligence scans on a target.")
app.add_typer(scan_app, name="scan")
# ... (all existing scan commands)

# --- Defensive Intelligence Command Group ---
app.add_typer(defensive_app, name="defensive", help="Run defensive counter-intelligence scans on your own assets.")

# --- AI & Analysis Command Group ---
analysis_app = typer.Typer(help="Run AI-powered and historical analysis.")
app.add_typer(analysis_app, name="analysis")
# Add the sub-groups for different types of analysis
analysis_app.add_typer(ai_app, name="core", help="Run basic AI analysis (sentiment, SWOT).")
analysis_app.add_typer(diff_app, name="diff", help="Compare historical scans to detect changes.")
analysis_app.add_typer(forecast_app, name="forecast", help="Analyzes historical data to forecast potential events.")
analysis_app.add_typer(strategy_app, name="strategy", help="Generates a high-level strategic profile of a target.")
analysis_app.add_typer(signal_app, name="signal", help="Analyzes a target's footprint for strategic signals.") # <-- ADD THIS LINE


if __name__ == "__main__":
    app()