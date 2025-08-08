import typer
from modules.footprint import footprint_app
from modules.web_analyzer import web_app
from modules.business_intel import business_app
from modules.defensive import defensive_app # Import the new app

# Main Chimera Intel CLI Application
app = typer.Typer(
    name="Chimera Intel",
    help="A modular OSINT platform for corporate intelligence and counter-intelligence.",
    add_completion=False
)

# --- Offensive Intelligence Command Group ---
scan_app = typer.Typer(help="Run offensive intelligence scans on a target.")
app.add_typer(scan_app, name="scan")

# Add all the command modules to the 'scan' group
scan_app.add_typer(footprint_app, name="footprint", help="Gathers basic digital footprint (WHOIS, DNS, Subdomains).")
scan_app.add_typer(web_app, name="web", help="Analyzes web-specific data (Tech Stack, Traffic).")
scan_app.add_typer(business_app, name="business", help="Gathers business intelligence (Financials, News, Patents).")

# --- Defensive Intelligence Command Group ---
app.add_typer(defensive_app, name="defensive", help="Run defensive counter-intelligence scans on your own assets.")


if __name__ == "__main__":
    app()