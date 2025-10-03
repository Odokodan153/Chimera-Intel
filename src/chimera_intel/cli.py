import typer
from chimera_intel.core.logger_config import setup_logging
from chimera_intel.core.database import initialize_database
from chimera_intel.core.plugin_manager import discover_plugins
from chimera_intel.core.project_manager import project_app
from chimera_intel.core.briefing_generator import briefing_app
from chimera_intel.core.graph_cli import graph_app

# --- : Startup Banner ---
BANNER = """
  ____ _   _ ___ __  __ _____ ____      _       ___ _   _ _____ _____ _     
 / ___| | | |_ _|  \/  | ____|  _ \    / \     |_ _| \ | |_   _| ____| |    
| |   | |_| || || |\/| |  _| | |_) |  / _ \     | ||  \| | | | |  _| | |    
| |___|  _  || || |  | | |___|  _ <  / ___ \    | || |\  | | | | |___| |___ 
 \____|_| |_|___|_|  |_|_____|_| \_\/_/   \_\  |___|_| \_| |_| |_____|_____|
"""


def get_cli_app():
    """
    Creates the core Typer application without loading plugins.
    This allows plugins to be loaded dynamically at runtime.
    """
    app = typer.Typer(
        name="Chimera Intel",
        help="A modular OSINT platform powered by an AI analysis core.",
        add_completion=False,
        rich_markup_mode="markdown",
    )

    # --- Core Command Registration ---
    app.add_typer(project_app, name="project", help="Manage intelligence projects.")
    app.add_typer(briefing_app, name="briefing", help="Generate AI-powered executive briefings.")  # <-- ADDED
    app.add_typer(graph_app, name="graph", help="Interact with the Chimera Intelligence Graph.")

    @app.command(name="version", help="Show Chimera Intel version.")
    def version():
        """Show Chimera Intel version."""
        typer.echo("Chimera Intel v1.0.0")

    return app


app = get_cli_app()


def main():
    """
    Main entry point for the Chimera Intel CLI application.
    Initializes the environment, discovers and loads plugins, then runs the app.
    """
    print(BANNER)
    setup_logging()
    try:
        initialize_database()
    except ConnectionError:
        # Allow the CLI to continue without a database connection for basic commands.
        pass

    # Discover and load plugins at runtime
    plugins = discover_plugins()
    for plugin in plugins:
        app.add_typer(plugin.app, name=plugin.name)

    # Run the fully configured app
    app()


if __name__ == "__main__":
    main()
