"""
Main Command-Line Interface (CLI) entry point for the Chimera Intel application.

This script uses the Typer library to build a powerful and user-friendly CLI.
It orchestrates the application by importing and registering command groups (sub-apps)
from the various core modules. It also initializes the logging system and database.
"""

import typer
from chimera_intel.core.logger_config import setup_logging
from chimera_intel.core.database import initialize_database
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

app = typer.Typer(
    name="Chimera Intel",
    help="A modular OSINT platform powered by an AI analysis core.",
    add_completion=False,  # Shell completion can be noisy; disabled by default.
    rich_markup_mode="markdown",  # Allows for rich formatting in help text.
)


def main():
    """
    Main entry point for the Chimera Intel CLI application.
    Initializes logging, database, and dynamically loads all plugins.
    """
    print(BANNER)
    setup_logging()
    initialize_database()

    plugins = discover_plugins()
    # Group plugins by their top-level command name

    grouped_plugins = {}
    for plugin in plugins:
        if plugin.name not in grouped_plugins:
            # Create a new top-level Typer app for this group if it doesn't exist

            grouped_plugins[plugin.name] = typer.Typer(
                help=f"Commands for {plugin.name} intelligence."
            )
            app.add_typer(grouped_plugins[plugin.name], name=plugin.name)
        # Add the plugin's app as a subcommand to the group
        # The plugin's own app might contain nested commands.

        sub_app = plugin.app
        # The name of the subcommand is derived from the plugin's main Typer app help text or name.
        # This is a bit of a workaround to get the subcommand name.

        sub_name = sub_app.info.name or plugin.__class__.__name__.lower().replace(
            "plugin", ""
        )

        # If the plugin's app has commands, add it as a typer subcommand

        if sub_app.registered_commands:
            grouped_plugins[plugin.name].add_typer(sub_app, name=sub_name)
    # This allows the script to be run directly during development.

    app()


if __name__ == "__main__":
    main()
