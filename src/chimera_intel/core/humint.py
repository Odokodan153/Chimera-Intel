"""
Human Intelligence (HUMINT) Management Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .database import get_db
from .schemas import HumintSource, HumintReport
from .ai_core import perform_generative_task

console = Console()

humint_app = typer.Typer(
    name="humint",
    help="Manages intelligence derived from human sources.",
)


@humint_app.command("add-source", help="Add a new human source to the database.")
def add_source(
    name: Annotated[
        str,
        typer.Option(
            "--name", "-n", help="The name or codename of the source.", prompt=True
        ),
    ],
    reliability: Annotated[
        str,
        typer.Option(
            "--reliability", "-r", help="Reliability score (e.g., A1, B2).", prompt=True
        ),
    ],
    expertise: Annotated[
        str,
        typer.Option(
            "--expertise", "-e", help="The source's area of expertise.", prompt=True
        ),
    ],
):
    """Creates and manages a database of human sources."""
    db = next(get_db())
    db_source = HumintSource(name=name, reliability=reliability, expertise=expertise)
    db.add(db_source)
    db.commit()
    console.print(f"[bold green]✅ Source '{name}' added successfully.[/bold green]")


@humint_app.command("list-sources", help="List all managed human sources.")
def list_sources():
    """Displays all human sources currently in the database."""
    db = next(get_db())
    sources = db.query(HumintSource).all()
    if not sources:
        console.print("[yellow]No human sources found in the database.[/yellow]")
        return
    table = Table(title="Managed Human Sources")
    table.add_column("ID", style="cyan")
    table.add_column("Name/Codename", style="magenta")
    table.add_column("Reliability", style="green")
    table.add_column("Expertise", style="yellow")

    for source in sources:
        table.add_row(str(source.id), source.name, source.reliability, source.expertise)
    console.print(table)


@humint_app.command("add-report", help="Log a new report from a human source.")
def add_report(
    source: Annotated[
        str,
        typer.Option(
            "--source",
            "-s",
            help="The name/codename of the source for this report.",
            prompt=True,
        ),
    ],
    file: Annotated[
        str,
        typer.Option(
            "--file",
            "-f",
            help="Path to the text file containing the report.",
            prompt=True,
        ),
    ],
    analyze: Annotated[
        bool,
        typer.Option(
            "--analyze", "-a", help="Use AI to extract entities and relationships."
        ),
    ] = False,
):
    """Securely logs and tags interview notes and field reports."""
    db = next(get_db())
    db_source = db.query(HumintSource).filter(HumintSource.name == source).first()
    if not db_source:
        console.print(
            f"[bold red]Error:[/bold red] Source '{source}' not found. Please add the source first."
        )
        raise typer.Exit(code=1)
    if not os.path.exists(file):
        console.print(f"[bold red]Error:[/bold red] Report file not found at '{file}'.")
        raise typer.Exit(code=1)
    with open(file, "r", encoding="utf-8") as f:
        content = f.read()
    db_report = HumintReport(content=content, source_id=db_source.id)
    db.add(db_report)
    db.commit()
    console.print(
        f"[bold green]✅ Report from '{source}' logged successfully.[/bold green]"
    )

    if analyze:
        console.print("Analyzing report with AI core to map relationships...")
        prompt = f"Analyze the following intelligence report. Extract all key entities (People, Organizations, Locations) and describe the relationships between them in a list format:\n\n---\n\n{content}"
        analysis_result = perform_generative_task(prompt)
        console.print(
            Panel(
                analysis_result,
                title="[bold blue]AI-Extracted Relationships[/bold blue]",
                border_style="blue",
            )
        )
