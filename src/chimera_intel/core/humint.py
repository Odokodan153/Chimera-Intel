"""
HUMINT (Human Intelligence) Module for Chimera Intel.

Allows for the structured storage, retrieval, and AI-powered analysis of
qualitative, human-derived intelligence reports.
"""

import typer
from typing import Optional
import psycopg2

from .database import get_db_connection
from .ai_core import generate_swot_from_data
from .config_loader import API_KEYS
from .utils import console

humint_app = typer.Typer(
    name="humint",
    help="Manages Human Intelligence (HUMINT) sources and reports.",
)


def add_humint_source(name: str, reliability: str, expertise: str) -> None:
    """Adds a new HUMINT source to the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO humint_sources (name, reliability, expertise) VALUES (%s, %s, %s)",
            (name, reliability, expertise),
        )
        conn.commit()
        cursor.close()
        conn.close()
        console.print(
            f"[bold green]Successfully added HUMINT source:[/bold green] {name}"
        )
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not add source: {e}")


def add_humint_report(source_name: str, content: str) -> None:
    """Adds a new HUMINT report linked to a source."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # First, get the source ID

        cursor.execute("SELECT id FROM humint_sources WHERE name = %s", (source_name,))
        source_record = cursor.fetchone()
        if not source_record:
            console.print(
                f"[bold red]Error:[/bold red] Source '{source_name}' not found."
            )
            return
        source_id = source_record[0]
        cursor.execute(
            "INSERT INTO humint_reports (source_id, content) VALUES (%s, %s)",
            (source_id, content),
        )
        conn.commit()
        cursor.close()
        conn.close()
        console.print(
            f"[bold green]Successfully added HUMINT report from source:[/bold green] {source_name}"
        )
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not add report: {e}")


def analyze_humint_reports(topic: str) -> Optional[str]:
    """Uses AI to analyze all HUMINT reports related to a specific topic."""
    api_key = API_KEYS.google_api_key
    if not api_key:
        console.print("[bold red]Error:[/bold red] Google API key not configured.")
        return None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # This is a simple text search; a real implementation might use more advanced NLP

        cursor.execute(
            "SELECT s.name, s.reliability, r.content FROM humint_reports r JOIN humint_sources s ON r.source_id = s.id WHERE r.content ILIKE %s",
            (f"%{topic}%",),
        )
        records = cursor.fetchall()
        cursor.close()
        conn.close()

        if not records:
            console.print(
                f"[yellow]No HUMINT reports found matching the topic: {topic}[/yellow]"
            )
            return None
        reports_summary = "\n".join(
            [
                f"- Source: {r[0]} (Reliability: {r[1]})\n  - Report: {r[2]}"
                for r in records
            ]
        )

        prompt = f"""
        As an intelligence analyst, synthesize the following raw human intelligence (HUMINT) reports.
        Your task is to produce a concise intelligence summary based on the provided data.
        Identify key themes, potential biases based on source reliability, and any actionable insights.

        **Raw HUMINT Reports:**
        {reports_summary}
        """

        ai_result = generate_swot_from_data(prompt, api_key)
        if ai_result.error:
            console.print(f"[bold red]AI Analysis Error:[/bold red] {ai_result.error}")
            return None
        return ai_result.analysis_text
    except (psycopg2.Error, ConnectionError) as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not analyze reports: {e}"
        )
        return None


@humint_app.command("add-source")
def cli_add_source(
    name: str = typer.Option(
        ..., "--name", "-n", help="The unique name or codename of the source."
    ),
    reliability: str = typer.Option(
        ..., "--reliability", "-r", help="Reliability code (e.g., A1, B2)."
    ),
    expertise: str = typer.Option(
        ...,
        "--expertise",
        "-e",
        help="Area of expertise (e.g., 'Cybercrime', 'Geopolitics').",
    ),
):
    """Adds a new HUMINT source to the database."""
    add_humint_source(name, reliability, expertise)


@humint_app.command("add-report")
def cli_add_report(
    source_name: str = typer.Option(
        ..., "--source", "-s", help="The name of the source providing the report."
    ),
    content: str = typer.Option(
        ...,
        "--content",
        "-c",
        help="The content of the intelligence report.",
        prompt=True,
    ),
):
    """Adds a new HUMINT report from a specified source."""
    add_humint_report(source_name, content)


@humint_app.command("analyze")
def cli_analyze(
    topic: str = typer.Argument(
        ..., help="The topic or keyword to analyze across all HUMINT reports."
    )
):
    """Analyzes all HUMINT reports related to a specific topic."""
    analysis = analyze_humint_reports(topic)
    if analysis:
        console.print(
            f"\n[bold green]AI-Powered HUMINT Analysis for '{topic}':[/bold green]"
        )
        console.print(analysis)
