import typer
from modules.footprint import footprint_app
from modules.web_analyzer import web_app
from modules.business_intel import business_app
from modules.defensive import defensive_app
from modules.ai_core import ai_app
from modules.database import initialize_database # <-- NEW IMPORT

# Initialize the database and table if they don't exist
# This function will run once every time the `chimera` command is executed.
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
scan_app.add_typer(footprint_app, name="footprint", help="Gathers basic digital footprint (WHOIS, DNS, Subdomains).")
scan_app.add_typer(web_app, name="web", help="Analyzes web-specific data (Tech Stack, Traffic).")
scan_app.add_typer(business_app, name="business", help="Gathers business intelligence (Financials, News, Patents).")

# --- Defensive Intelligence Command Group ---
app.add_typer(defensive_app, name="defensive", help="Run defensive counter-intelligence scans on your own assets.")

# --- AI Core Command Group ---
app.add_typer(ai_app, name="ai", help="Run AI-powered analysis on collected data.")


if __name__ == "__main__":
    app()