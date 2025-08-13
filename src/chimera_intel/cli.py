import typer

from chimera_intel.core.footprint import footprint_app
from chimera_intel.core.web_analyzer import web_app
from chimera_intel.core.business_intel import business_app
from chimera_intel.core.defensive import defensive_app
from chimera_intel.core.ai_core import ai_app
from chimera_intel.core.database import initialize_database
from chimera_intel.core.differ import diff_app
from chimera_intel.core.forecaster import forecast_app
from chimera_intel.core.strategist import strategy_app
from chimera_intel.core.signal_analyzer import signal_app
from chimera_intel.core.reporter import report_app
from chimera_intel.core.grapher import graph_app
from chimera_intel.core.social_analyzer import social_app

initialize_database()

app = typer.Typer(
    name="Chimera Intel",
    help="A modular OSINT platform powered by an AI analysis core.",
    add_completion=False
)

# --- Command Group Definitions ---
scan_app = typer.Typer(help="Run offensive intelligence scans on a target.")
app.add_typer(scan_app, name="scan")
scan_app.add_typer(footprint_app, name="footprint", help="Gathers basic digital footprint.")
scan_app.add_typer(web_app, name="web", help="Analyzes web-specific data.")
scan_app.add_typer(business_app, name="business", help="Gathers business intelligence.")

app.add_typer(defensive_app, name="defensive", help="Run defensive scans on your own assets.")

analysis_app = typer.Typer(help="Run AI-powered and historical analysis.")
app.add_typer(analysis_app, name="analysis")
analysis_app.add_typer(ai_app, name="core", help="Run basic AI analysis.")
analysis_app.add_typer(diff_app, name="diff", help="Compare historical scans.")
analysis_app.add_typer(forecast_app, name="forecast", help="Forecasts potential events.")
analysis_app.add_typer(strategy_app, name="strategy", help="Generates a strategic profile.")
analysis_app.add_typer(signal_app, name="signal", help="Analyzes for strategic signals.")
analysis_app.add_typer(social_app, name="social", help="Analyzes RSS feed content.")

report_app_group = typer.Typer(help="Generate reports from saved scan data.")
app.add_typer(report_app_group, name="report")
report_app_group.add_typer(report_app, name="pdf", help="Generate a PDF report.")
report_app_group.add_typer(graph_app, name="graph", help="Generate a visual graph report.")

if __name__ == "__main__":
    app()