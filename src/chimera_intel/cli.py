"""
Main Command-Line Interface (CLI) entry point for the Chimera Intel application.

This script uses the Typer library to build a powerful and user-friendly CLI.
It orchestrates the application by importing and registering command groups (sub-apps)
from the various core modules. It also initializes the logging system and database.
"""

import typer
from chimera_intel.core.logger_config import setup_logging
from chimera_intel.core.database import initialize_database
from chimera_intel.core.social_media_monitor import social_media_monitor_app
from chimera_intel.core.plugin_manager import discover_plugins
from chimera_intel.core.graph_analyzer import graph_app
from chimera_intel.core.social_analyzer import social_app as social_analyzer_app

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
# Find the 'scan' plugin's Typer app to add more commands to it

scan_app_found = None
for p in plugins:
    if p.name == "scan":
        scan_app_found = p.app
        break
if scan_app_found:
    # Find the social subcommand within the scan app

    social_subcommand = None
    for cmd in scan_app_found.registered_commands:
        if cmd.name == "social":
            # This is a CommandInfo object, we need its callback to find the Typer app

            if hasattr(cmd, "callback"):
                # In Typer, sub-Typer apps are often handled by a callback that holds the app
                # This part is tricky and might need adjustment based on Typer's internal structure
                # A simpler way is to ensure the social plugin itself handles this.
                # However, for this fix, we will assume a structure.
                # A better approach is to have a central registry of Typer apps.

                # Let's try to add it directly to the social_analyzer_app from the core

                social_analyzer_app.add_typer(
                    social_media_monitor_app,
                    name="monitor",
                    help="Monitor social media in real-time.",
                )
for plugin in plugins:
    app.add_typer(plugin.app, name=plugin.name)
app.add_typer(
    graph_app, name="graph", help="Entity relationship graphing and analysis."
)


if __name__ == "__main__":
    # This block allows the script to be run directly during development.
    # The 'project.scripts' in pyproject.toml is what enables the 'chimera' command after installation.

    app()
