"""
Cultural Intelligence (CULTINT) & Memetic Engineering Engine for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
from rich.console import Console
from rich.panel import Panel
import json

from .database import get_db, Scans
from .ai_core import perform_generative_task
from .schemas import ScanModel

console = Console()

cultint_app = typer.Typer(
    name="cultint",
    help="Performs Cultural Intelligence analysis to map belief systems.",
)


@cultint_app.command("map", help="Map the cultural and ideological terrain of a group.")
def cultint_map(
    project: Annotated[
        str,
        typer.Option(
            "--project",
            "-p",
            help="The project context representing the group to analyze.",
            prompt=True,
        ),
    ],
    sources: Annotated[
        str,
        typer.Option(
            "--sources",
            "-s",
            help="Comma-separated data sources to use (e.g., 'social,darkweb').",
            default="all",
        ),
    ],
):
    """
    Synthesizes unstructured data to identify core values, symbols, and
    foundational beliefs that define a group's identity.
    """
    console.print(
        f"Mapping cultural terrain for project '[bold yellow]{project}[/bold yellow]' using sources: [cyan]{sources}[/cyan]"
    )

    try:
        db = next(get_db())
        query = db.query(Scans).filter(Scans.project_name == project)

        if sources != "all":
            source_list = [s.strip() for s in sources.split(",")]
            # This assumes your module names align with the sources, e.g., 'social_osint', 'dark_web_osint'

            query = query.filter(Scans.module.in_([f"{s}_osint" for s in source_list]))
        scans = query.all()
        if not scans:
            console.print(
                f"[bold red]Error:[/bold red] No data found for the specified project and sources. Cannot generate map."
            )
            raise typer.Exit(code=1)
        # Synthesize a text-based summary of all relevant data

        data_summary = "\n\n---\n\n".join(
            [
                f"Source: {s.module}\nContent: {json.dumps(s.data, indent=2)}"
                for s in scans
            ]
        )

        # Construct the prompt for the AI core

        prompt = (
            "As an expert in cultural anthropology and memetic engineering, analyze the following collection of unstructured data from various sources (social media posts, forum discussions, etc.) related to a specific group. Your task is to produce a 'Cultural Terrain Map'. "
            "Identify and synthesize the following:\n"
            "1. **Core Values & Beliefs**: What are the foundational principles that members of this group hold dear?\n"
            "2. **Key Symbols & Language**: Are there specific words, phrases, images, or symbols that carry special meaning for this group?\n"
            "3. **Shared History & Grievances**: What are the key historical events or shared struggles that define their collective identity?\n"
            "4. **In-group/Out-group Dynamics**: How do they define themselves in opposition to other groups?\n\n"
            f"Here is the data:\n{data_summary}"
        )

        # Use the AI to generate the analysis

        analysis_result = perform_generative_task(prompt)

        console.print(
            Panel(
                analysis_result,
                title="[bold green]Cultural Terrain Map[/bold green]",
                border_style="green",
            )
        )
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during CULTINT analysis:[/bold red] {e}"
        )
        raise typer.Exit(code=1)
