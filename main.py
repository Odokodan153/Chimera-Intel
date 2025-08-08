import typer
from modules.footprint import footprint_app

# Main Chimera Intel CLI Application
app = typer.Typer(
    name="Chimera Intel",
    help="A modular OSINT platform for corporate intelligence and counter-intelligence.",
    add_completion=False
)

# Create a 'scan' command group
scan_app = typer.Typer()
app.add_typer(scan_app, name="scan", help="Run offensive intelligence scans on a target.")

# Add the footprint commands to the 'scan' group
scan_app.add_typer(footprint_app, name="footprint", help="Gathers basic digital footprint intelligence.")

if __name__ == "__main__":
    app()