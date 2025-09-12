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
    # Special handling for the social plugin to add the new monitor command
    if plugin.name == "scan":
        # The `plugin.app` is the Typer object for the 'scan' group
        # We need to find the 'social' subcommand within it
        for sub_app in plugin.app.registered_commands:
            if hasattr(sub_app, 'name') and sub_app.name == "social":
                # Now add the 'monitor' command to the 'social' subcommand
                sub_app.add_typer(social_media_monitor_app, name="monitor", help="Monitor social media in real-time.")
    
    # After potential modification, add the plugin's app to the main app
    app.add_typer(plugin.app, name=plugin.name)

if __name__ == "__main__":
    # This block allows the script to be run directly during development.
    # The 'project.scripts' in pyproject.toml is what enables the 'chimera' command after installation.

    app()