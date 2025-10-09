import logging
import json
from .schemas import IntelligenceReport
from typing import Optional, List
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Flowable
from reportlab.lib.styles import getSampleStyleSheet
import typer
from rich.console import Console

logger = logging.getLogger(__name__)


# --- Core Logic ---


def generate_executive_briefing(report: IntelligenceReport, output_path: str) -> bool:
    """Generates a one-page PDF executive briefing."""
    try:
        doc = SimpleDocTemplate(output_path)
        styles = getSampleStyleSheet()

        # FIX: Explicitly type story as a list of Flowables to resolve mypy error.

        story: List[Flowable] = []

        story.append(Paragraph(report.title, styles["h1"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph("Strategic Summary", styles["h2"]))
        story.append(Paragraph(report.strategic_summary, styles["BodyText"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph("Key Risk Indicators", styles["h2"]))

        for finding in report.key_findings:
            if finding.severity in ["High", "Critical"]:
                story.append(
                    Paragraph(
                        f"• ({finding.severity}) {finding.description}",
                        styles["BodyText"],
                    )
                )
        doc.build(story)
        return True
    except Exception as e:
        logger.error(f"Failed to generate PDF briefing: {e}")
        return False


def generate_technical_report(report: IntelligenceReport) -> str:
    """Generates a detailed technical report in JSON format."""
    return report.json(indent=2)


def generate_tactical_alert(report: IntelligenceReport) -> Optional[str]:
    """Generates a concise tactical alert for critical, time-sensitive information."""
    critical_finding = next(
        (f for f in report.key_findings if f.severity == "Critical"), None
    )
    if critical_finding:
        return f"CRITICAL ALERT: {critical_finding.description} (Confidence: {critical_finding.confidence*100:.0f}%)"
    return None


# --- CLI Integration ---


app = typer.Typer(
    name="disseminate",
    help="The Automated Dissemination & Briefing Suite.",
    no_args_is_help=True,
)


@app.command("generate")
def run_dissemination(
    report_file: str = typer.Argument(
        ..., help="Path to the finalized intelligence report (JSON)."
    ),
    output_prefix: str = typer.Argument(
        ..., help="File prefix for the generated outputs (e.g., 'report-xyz')."
    ),
):
    """Generates all dissemination products from an intelligence report."""
    console = Console()
    try:
        with open(report_file, "r") as f:
            report_data = json.load(f)
        report = IntelligenceReport(**report_data)
    except Exception as e:
        console.print(f"[bold red]Error loading report file:[/] {e}")
        return
    console.print(f"[bold]Generating intelligence products for '{report.title}'...[/]")

    # Executive Briefing

    pdf_path = f"{output_prefix}_executive_briefing.pdf"
    if generate_executive_briefing(report, pdf_path):
        console.print(f"✅ [green]Executive Briefing PDF generated at:[/] {pdf_path}")
    # Technical Report

    tech_path = f"{output_prefix}_technical_report.json"
    with open(tech_path, "w") as f:
        f.write(generate_technical_report(report))
    console.print(f"✅ [green]Technical Report JSON generated at:[/] {tech_path}")

    # Tactical Alert

    alert = generate_tactical_alert(report)
    if alert:
        console.print(f"🚨 [yellow]Tactical Alert generated:[/] {alert}")
    # API Endpoint (simulated by showing the JSON)

    console.print("\n[bold]API Endpoint Output:[/bold]")
    console.print(json.dumps(report.dict(), indent=2))
