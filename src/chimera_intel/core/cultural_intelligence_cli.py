import typer
from rich.console import Console
from rich.table import Table
from . import cultural_intelligence

console = Console()
cultural_app = typer.Typer(help="Tools for managing Cultural Intelligence profiles.")


@cultural_app.command("add")
def add_profile_cli(
    country_code: str = typer.Option(
        ..., "--code", "-c", help="Two-letter country code (e.g., 'US')."
    ),
    country_name: str = typer.Option(
        ..., "--name", "-n", help="Full name of the country."
    ),
    directness: int = typer.Option(
        ..., "--directness", "-d", help="Directness score (1-10)."
    ),
    formality: int = typer.Option(
        ..., "--formality", "-f", help="Formality score (1-10)."
    ),
    power_distance: int = typer.Option(
        ..., "--power", "-p", help="Hofstede Power Distance score."
    ),
    individualism: int = typer.Option(
        ..., "--individualism", "-i", help="Hofstede Individualism score."
    ),
    uncertainty_avoidance: int = typer.Option(
        ..., "--uncertainty", "-u", help="Hofstede Uncertainty Avoidance score."
    ),
):
    """Adds a new or updates an existing cultural profile to the database."""
    profile_data = {
        "country_code": country_code.upper(),
        "country_name": country_name,
        "directness": directness,
        "formality": formality,
        "power_distance": power_distance,
        "individualism": individualism,
        "uncertainty_avoidance": uncertainty_avoidance,
    }
    cultural_intelligence.add_cultural_profile(profile_data)


@cultural_app.command("populate")
def populate_data_cli():
    """Populates the database with initial, example cultural profiles."""
    console.print(
        "[yellow]Populating database with initial cultural profiles...[/yellow]"
    )
    cultural_intelligence.populate_initial_cultural_data()


@cultural_app.command("list")
def list_profiles_cli():
    """Lists all cultural profiles currently stored in the database."""
    # This function needs to be added to cultural_intelligence.py
    # For now, we'll assume it exists.

    profiles = (
        cultural_intelligence.get_all_cultural_profiles()
    )  # We will create this function next

    if not profiles:
        console.print("[yellow]No cultural profiles found in the database.[/yellow]")
        return
    table = Table(
        title="Stored Cultural Intelligence Profiles",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Code")
    table.add_column("Country")
    table.add_column("Directness")
    table.add_column("Formality")
    table.add_column("Power Distance")
    table.add_column("Individualism")
    table.add_column("Uncertainty Avoidance")

    for profile in profiles:
        table.add_row(
            profile["country_code"],
            profile["country_name"],
            str(profile["directness"]),
            str(profile["formality"]),
            str(profile["power_distance"]),
            str(profile["individualism"]),
            str(profile["uncertainty_avoidance"]),
        )
    console.print(table)
