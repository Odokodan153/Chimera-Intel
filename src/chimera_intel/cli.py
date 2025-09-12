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
from chimera_intel.core.corporate_records import corporate_records_app
from chimera_intel.core.tpr_engine import tpr_app
from chimera_intel.core.geo_osint import geo_osint_app
from chimera_intel.core.corporate_intel import corporate_intel_app
from chimera_intel.core.offensive import offensive_app
from chimera_intel.core.internal import internal_app
from chimera_intel.core.automation import automation_app, connect_app
from chimera_intel.core.recon import recon_app
from chimera_intel.core.blockchain_osint import blockchain_app
from chimera_intel.core.code_intel import code_intel_app
from chimera_intel.core.ttp_mapper import ttp_app
from chimera_intel.core.physical_osint import physical_osint_app
from chimera_intel.core.ecosystem_intel import ecosystem_app
from chimera_intel.core.cybint import cybint_app
from chimera_intel.core.project_manager import project_app
from chimera_intel.core.geo_strategist import geo_strategist_app
from chimera_intel.core.project_reporter import project_report_app
from chimera_intel.core.finint import finint_app
from chimera_intel.core.legint import legint_app
from chimera_intel.core.threat_hunter import threat_hunter_app
from chimera_intel.core.pestel_analyzer import pestel_analyzer_app
from chimera_intel.core.competitive_analyzer import competitive_analyzer_app
from chimera_intel.core.lead_suggester import lead_suggester_app
from chimera_intel.core.daemon import daemon_app
from chimera_intel.core.briefing_generator import present_app
from chimera_intel.core.plugin_manager import discover_plugins

# --- : Startup Banner ---
# This will be printed every time the CLI is invoked.


BANNER = """
  ____ _   _ ___ __  __ _____ ____      _       ___ _   _ _____ _____ _     
 / ___| | | |_ _|  \/  | ____|  _ \    / \     |_ _| \ | |_   _| ____| |    
| |   | |_| || || |\/| |  _| | |_) |  / _ \     | ||  \| | | | |  _| | |    
| |___|  _  || || |  | | |___|  _ <  / ___ \    | || |\  | | | | |___| |___ 
 \____|_| |_|___|_|  |_|_____|_| \_\/_/   \_\  |___|_| \_| |_| |_____|_____|
"""
print(BANNER)

setup_logging()

# Initialize the database to ensure the schema is ready.


initialize_database()

# --- Main Application Definition ---
# This is the top--level Typer application.


app = typer.Typer(
    name="Chimera Intel",
    help="A modular OSINT platform powered by an AI analysis core.",
    add_completion=False,  # Shell completion can be noisy; disabled by default.
    rich_markup_mode="markdown",  # Allows for rich formatting in help text.
)

# --- Dynamic Plugin Registration ---
# The CLI now discovers and loads all installed plugins automatically.
plugins = discover_plugins()
for plugin in plugins:
    app.add_typer(plugin.app, name=plugin.name)


if __name__ == "__main__":
    # This block allows the script to be run directly during development.
    # The 'project.scripts' in pyproject.toml is what enables the 'chimera' command after installation.

    app()