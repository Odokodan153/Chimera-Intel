"""
Main Command-Line Interface (CLI) entry point for the Chimera Intel application.

This script uses the Typer library to build a powerful and user-friendly CLI.
It orchestrates the application by importing and registering command groups (sub-apps)
from the various core modules. It also initializes the logging system and database.
"""

import typer
from chimera_intel.core.logger_config import setup_logging
from chimera_intel.core.database import initialize_database
from chimera_intel.core.footprint import footprint_app
from chimera_intel.core.web_analyzer import web_app
from chimera_intel.core.business_intel import business_app
from chimera_intel.core.defensive import defensive_app
from chimera_intel.core.ai_core import ai_app
from chimera_intel.core.differ import diff_app
from chimera_intel.core.forecaster import forecast_app
from chimera_intel.core.strategist import strategy_app
from chimera_intel.core.signal_analyzer import signal_app
from chimera_intel.core.reporter import report_app
from chimera_intel.core.grapher import graph_app
from chimera_intel.core.social_analyzer import social_app
from chimera_intel.core.vulnerability_scanner import vulnerability_app
from chimera_intel.core.social_osint import social_osint_app
from chimera_intel.core.dark_web_osint import dark_web_app
from chimera_intel.core.cloud_osint import cloud_osint_app
from chimera_intel.core.personnel_osint import personnel_osint_app

setup_logging()

# Initialize the database to ensure the schema is ready.


initialize_database()

# --- Main Application Definition ---
# This is the top-level Typer application.


app = typer.Typer(
    name="Chimera Intel",
    help="A modular OSINT platform powered by an AI analysis core.",
    add_completion=False,  # Shell completion can be noisy; disabled by default.
    rich_markup_mode="markdown",  # Allows for rich formatting in help text.
)

# --- Command Group Registration ---
# The following sections register the imported applications as command groups,
# creating a hierarchical CLI structure like 'chimera <group> <command>'.

# 1. 'scan' command group for offensive intelligence gathering.


scan_app = typer.Typer(help="Run offensive intelligence scans on a target.")
app.add_typer(scan_app, name="scan")
scan_app.add_typer(
    footprint_app,
    name="footprint",
    help="Gathers basic digital footprint (WHOIS, DNS, Subdomains).",
)
scan_app.add_typer(
    web_app, name="web", help="Analyzes web-specific data (Tech Stack, Traffic)."
)
scan_app.add_typer(
    business_app,
    name="business",
    help="Gathers business intelligence (Financials, News, Patents).",
)
scan_app.add_typer(
    social_app, name="social", help="Analyzes content from a target's RSS feed."
)
scan_app.add_typer(
    social_osint_app, name="profiles", help="Finds social media profiles by username."
)
scan_app.add_typer(
    cloud_osint_app,
    name="cloud",
    help="Scans for exposed cloud assets like S3 buckets.",
)
scan_app.add_typer(
    personnel_osint_app,
    name="personnel",
    help="Gathers intelligence on company employees.",
)

# 2. 'defensive' command group for internal security and counter-intelligence.


defensive_group_app = typer.Typer(
    help="Run defensive and vulnerability scans on your own assets."
)
app.add_typer(defensive_group_app, name="defensive")
defensive_group_app.add_typer(
    defensive_app,
    name="checks",
    help="Run standard defensive checks (breaches, leaks, etc.).",
)
defensive_group_app.add_typer(
    vulnerability_app, name="vuln", help="Run vulnerability scans on discovered assets."
)
defensive_group_app.add_typer(
    dark_web_app, name="darkweb", help="Searches the dark web for leaked data."
)


# 3. 'analysis' command group for AI-powered and historical data analysis.


analysis_app = typer.Typer(help="Run AI-powered and historical analysis.")
app.add_typer(analysis_app, name="analysis")
analysis_app.add_typer(
    ai_app, name="core", help="Run basic AI analysis (Sentiment, SWOT)."
)
analysis_app.add_typer(
    diff_app, name="diff", help="Compare two historical scans to detect changes."
)
analysis_app.add_typer(
    forecast_app,
    name="forecast",
    help="Forecasts potential future events from historical data.",
)
analysis_app.add_typer(
    strategy_app,
    name="strategy",
    help="Generates an AI-powered strategic profile of a target.",
)
analysis_app.add_typer(
    signal_app, name="signal", help="Analyzes data for unintentional strategic signals."
)


# 4. 'report' command group for generating output files from saved data.


report_app_group = typer.Typer(help="Generate reports from saved JSON scan data.")
app.add_typer(report_app_group, name="report")
report_app_group.add_typer(report_app, name="pdf", help="Generate a formal PDF report.")
report_app_group.add_typer(
    graph_app, name="graph", help="Generate a visual, interactive HTML graph."
)


if __name__ == "__main__":
    # This block allows the script to be run directly during development.
    # The 'project.scripts' in pyproject.toml is what enables the 'chimera' command after installation.

    app()
