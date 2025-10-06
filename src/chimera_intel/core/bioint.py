"""
Biological Intelligence (BIOINT) & Genetic Reconnaissance Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
from rich.console import Console
from Bio import Entrez, SeqIO
import io

console = Console()

bioint_app = typer.Typer(
    name="bioint",
    help="Biological Intelligence (BIOINT) & Genetic Reconnaissance.",
)


def search_genbank(query: str, email: str, max_results: int = 5):
    """
    Searches the NCBI GenBank database for a specific genetic sequence or term.
    """
    Entrez.email = email
    handle = Entrez.esearch(db="nucleotide", term=query, retmax=max_results)
    record = Entrez.read(handle)
    handle.close()

    if not record["IdList"]:
        return []
    id_list = record["IdList"]
    handle = Entrez.efetch(db="nucleotide", id=id_list, rettype="gb", retmode="text")
    records_text = handle.read()
    handle.close()

    # Use StringIO to parse the text records with SeqIO

    records = list(SeqIO.parse(io.StringIO(records_text), "genbank"))
    return records


@bioint_app.command(
    "monitor-sequences",
    help="Monitor a public genetic database for specific sequences.",
)
def monitor_sequences(
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help="The gene fragment, marker, or term to search for.",
            prompt=True,
        ),
    ],
    db: Annotated[
        str,
        typer.Option("--db", "-d", help="The database to monitor.", default="GenBank"),
    ],
    email: Annotated[
        str,
        typer.Option(
            "--email", "-e", help="Your email address (required by NCBI).", prompt=True
        ),
    ],
):
    """
    Continuously scans public genetic sequence databases for specific gene fragments,
    synthetic markers, or sequences related to patented research or pathogens.
    """
    console.print(
        f"Monitoring [bold cyan]{db}[/bold cyan] for target: '[yellow]{target}[/yellow]'"
    )

    if db.lower() != "genbank":
        console.print(
            "[bold red]Error:[/bold red] Only 'GenBank' is supported at this time."
        )
        raise typer.Exit(code=1)
    try:
        results = search_genbank(target, email)
        if not results:
            console.print("[yellow]No matching sequences found.[/yellow]")
            raise typer.Exit()
        console.print(
            f"\n--- [bold green]Found {len(results)} Matching Sequences[/bold green] ---"
        )
        for record in results:
            console.print(f"\n> [bold]Accession ID:[/] {record.id}")
            console.print(f"  [bold]Description:[/] {record.description}")
            console.print(f"  [bold]Sequence Length:[/] {len(record.seq)} bp")
        console.print("---------------------------------")
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during BIOINT monitoring:[/bold red] {e}"
        )
        raise typer.Exit(code=1)
