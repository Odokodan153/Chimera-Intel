import typer
import json
from reportlab.platypus import (  # type: ignore
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image,
    Flowable,
    BaseDocTemplate,
    Frame,
    PageTemplate,
)
from reportlab.lib.styles import getSampleStyleSheet  # type: ignore
from reportlab.lib import colors  # type: ignore
from reportlab.lib.pagesizes import letter  # type: ignore
from reportlab.lib.units import inch  # type: ignore
from typing import Dict, Any, List, Optional
import logging
from .utils import console
import os
from .database import get_aggregated_data_for_target
from .config_loader import CONFIG
from .graph_db import build_and_save_graph

# Get a logger instance for this specific file


logger = logging.getLogger(__name__)


# --- NEW: Custom Footer Function ---


def footer(canvas, doc):
    """
    This function is called on each page and draws the footer text.
    It pulls the footer content directly from the global CONFIG object.
    """
    canvas.saveState()
    canvas.setFont("Helvetica", 9)
    # Use the footer_text from the loaded config.yaml

    footer_text = CONFIG.reporting.pdf.footer_text
    canvas.drawString(inch, 0.75 * inch, f"{footer_text} | Page {doc.page}")
    canvas.restoreState()


def generate_pdf_report(json_data: Dict[str, Any], output_path: str) -> None:
    """
    Generates a professional PDF report from a JSON scan result with customizations.
    This function uses the ReportLab library to construct a PDF document. It iterates
    through the modules and sections of the input JSON data, creating titles,
    paragraphs, and tables for each part. It now includes a logo, custom title,
    and footer based on the settings in config.yaml.

    Args:
        json_data (Dict[str, Any]): The loaded JSON data from a scan.
        output_path (str): The path where the generated PDF file will be saved.
    """
    try:
        # Use BaseDocTemplate to allow for custom page templates (for the footer)

        doc = BaseDocTemplate(output_path)
        styles = getSampleStyleSheet()
        story: List[Flowable] = []

        # --- Title Page ---

        logo_path = CONFIG.reporting.pdf.logo_path
        if logo_path and os.path.exists(logo_path):
            try:
                logo = Image(logo_path, width=2 * inch, height=2 * inch)
                logo.hAlign = "CENTER"
                story.append(logo)
                story.append(Spacer(1, 0.25 * inch))
            except Exception as e:
                logger.warning(f"Could not load logo image from {logo_path}: {e}")
        story.append(Paragraph(CONFIG.reporting.pdf.title_text, styles["h1"]))
        story.append(Paragraph("Intelligence Report", styles["h2"]))
        target = json_data.get("domain") or json_data.get("company", "Unknown Target")
        story.append(Paragraph(f"Target: {target}", styles["h3"]))
        story.append(Spacer(1, 0.5 * inch))

        # --- Report Content ---

        for module_name, module_data in json_data.items():
            if isinstance(module_data, dict):
                story.append(
                    Paragraph(module_name.replace("_", " ").title(), styles["h2"])
                )
                for section_name, section_data in module_data.items():
                    if not isinstance(section_data, dict):
                        continue
                    story.append(
                        Paragraph(section_name.replace("_", " ").title(), styles["h3"])
                    )
                    table_data = []
                    if "results" in section_data and isinstance(
                        section_data["results"], list
                    ):
                        if section_data["results"] and isinstance(
                            section_data["results"][0], dict
                        ):
                            headers = list(section_data["results"][0].keys())
                            table_data.append(headers)
                            for item in section_data["results"]:
                                table_data.append(
                                    [str(item.get(h, "N/A")) for h in headers]
                                )
                        else:  # Handle list of simple strings
                            table_data = [[item] for item in section_data["results"]]
                    else:
                        table_data = [
                            [key, str(value)] for key, value in section_data.items()
                        ]
                    if table_data:
                        t = Table(table_data, repeatRows=1)
                        t.setStyle(
                            TableStyle(
                                [
                                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                                    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                ]
                            )
                        )
                        story.append(t)
                    story.append(Spacer(1, 0.2 * inch))
        frame = Frame(
            doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="normal"
        )
        template = PageTemplate(id="main_template", frames=[frame], onPage=footer)
        doc.addPageTemplates([template])
        doc.build(story)
        logger.info("Successfully generated PDF report at: %s", output_path)
    except Exception as e:
        logger.error("An error occurred during PDF generation: %s", e, exc_info=True)

def generate_threat_briefing(json_data: Dict[str, Any], output_path: str) -> None:
    """
    Generates a concise, one-page executive threat briefing
    from an aggregated database result.
    """
    try:
        doc = BaseDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story: List[Flowable] = []

        # --- Title ---
        story.append(Paragraph("Executive Threat Briefing", styles["h1"]))
        
        # Read target from the root of the aggregated data
        target = json_data.get("target", "Unknown Target")
        story.append(Paragraph(f"Target: {target}", styles["h2"]))
        story.append(Spacer(1, 0.25 * inch))

        # Get the nested modules dictionary
        modules = json_data.get("modules", {})

        # --- 1. Critical Findings (Top 5) ---
        story.append(Paragraph("Critical Findings", styles["h3"]))
        
        critical_findings = []
        
        # Extract critical vulnerabilities
        if (
            "vulnerability_scanner" in modules
            and "scanned_hosts" in modules["vulnerability_scanner"]
        ):
            for host in modules["vulnerability_scanner"]["scanned_hosts"]:
                for port in host.get("open_ports", []):
                    for cve in port.get("vulnerabilities", []):
                        if cve.get("cvss_score", 0) >= 9.0:
                            critical_findings.append(
                                f"<b>Critical CVE:</b> {cve['id']} (Score: {cve['cvss_score']}) on {host['host']}:{port['port']}"
                            )
        
        # Extract data breaches
        if (
            "defensive_breaches" in modules
            and "hibp" in modules["defensive_breaches"]
        ):
            breaches = modules["defensive_breaches"]["hibp"].get("breaches")
            if breaches:
                critical_findings.append(
                    f"<b>Data Breaches:</b> Target associated with {len(breaches)} known breaches."
                )

        if not critical_findings:
            critical_findings.append("No critical findings identified in this dataset.")

        for finding in critical_findings[:5]: # Limit to top 5
            story.append(Paragraph(f"• {finding}", styles["BodyText"]))
        story.append(Spacer(1, 0.2 * inch))

        # --- 2. Attack Surface Summary ---
        story.append(Paragraph("Attack Surface Summary", styles["h3"]))
        as_summary = []
        if "footprint" in modules:
            subs = modules["footprint"].get("subdomains", {}).get("total_unique", 0)
            ips = len(modules["footprint"].get("dns_records", {}).get("A", []))
            as_summary.append(f"<b>{subs}</b> subdomains and <b>{ips}</b> unique IP addresses identified.")
        
        if "vulnerability_scanner" in modules:
            ports = 0
            for host in modules["vulnerability_scanner"].get("scanned_hosts", []):
                ports += len(host.get("open_ports", []))
            if ports > 0:
                as_summary.append(f"<b>{ports}</b> open ports discovered across scanned hosts.")
        
        if not as_summary:
            as_summary.append("Attack surface data not available.")
            
        for item in as_summary:
            story.append(Paragraph(f"• {item}", styles["BodyText"]))
        story.append(Spacer(1, 0.2 * inch))

        # --- 3. Actionable Recommendations ---
        story.append(Paragraph("Actionable Recommendations", styles["h3"]))
        recos = []
        if any("Critical CVE" in f for f in critical_findings):
            recos.append("<b>Patching:</b> Immediately address all Critical (9.0+) CVEs identified.")
        if any("Data Breaches" in f for f in critical_findings):
            recos.append("<b>Credentials:</b> Force password rotation for all employees on associated domains.")
        if not recos:
            recos.append("<b>Monitoring:</b> Continue routine monitoring of the target's footprint.")
            
        for item in recos:
            story.append(Paragraph(f"• {item}", styles["BodyText"]))

        # --- Build ---
        frame = Frame(
            doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="normal"
        )
        template = PageTemplate(id="main_template", frames=[frame], onPage=footer)
        doc.addPageTemplates([template])
        doc.build(story)
        logger.info("Successfully generated threat briefing at: %s", output_path)

    except Exception as e:
        logger.error("An error occurred during briefing generation: %s", e, exc_info=True)

# --- Typer CLI Application ---


report_app = typer.Typer()


@report_app.command("pdf")
def create_pdf_report(
    json_file: str = typer.Argument(..., help="Path to the JSON scan result file."),
    output_file: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to save the PDF report. Defaults to '<target>.pdf'.",
    ),
):
    """
    Creates a PDF report from a saved JSON scan file.
    """
    logger.info("Generating PDF report from: %s", json_file)

    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error("Input file for PDF report not found at '%s'", json_file)
        raise typer.Exit(code=1)
    except json.JSONDecodeError:
        logger.error("Invalid JSON in file '%s'", json_file)
        raise typer.Exit(code=1)
    if not output_file:
        target_name = data.get("domain") or data.get("company", "report")
        output_path = f"{target_name.replace('.', '_')}.pdf"
    else:
        output_path = output_file
    generate_pdf_report(data, output_path)

@report_app.command("briefing")
def create_briefing_report(
    json_file: str = typer.Argument(..., help="Path to a JSON scan file identifying the target."),
    output_file: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to save the PDF briefing. Defaults to '<target>_briefing.pdf'.",
    ),
):
    """
    Creates a one-page executive threat briefing by aggregating all
    historical database data for the target specified in the JSON file.
    """
    logger.info("Generating threat briefing for target in: %s", json_file)

    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error("Input file for briefing not found at '%s'", json_file)
        raise typer.Exit(code=1)
    except json.JSONDecodeError:
        logger.error("Invalid JSON in file '%s'", json_file)
        raise typer.Exit(code=1)

    # Use the JSON file to identify the target
    target_name = data.get("domain") or data.get("company", "report")
    if target_name == "report":
        logger.error("Could not determine 'domain' or 'company' from JSON file.")
        raise typer.Exit(code=1)

    if not output_file:
        output_path = f"{target_name.replace('.', '_')}_briefing.pdf"
    else:
        output_path = output_file
        
    # --- THIS IS THE "REAL DEF" ---
    # Fetch all aggregated data for that target from the database
    logger.info(f"Fetching all historical data for target: {target_name}")
    aggregated_data = get_aggregated_data_for_target(target_name)
    
    if not aggregated_data or not aggregated_data.get("modules"):
        logger.error(f"No aggregated data found in the database for target '{target_name}'. Cannot generate briefing.")
        raise typer.Exit(code=1)
    
    # Use the complete aggregated data to generate the report
    generate_threat_briefing(aggregated_data, output_path)

def generate_graph_report(json_data: Dict[str, Any], output_path: str):
    """Generates an HTML graph report for a target."""
    try:
        build_and_save_graph(json_data, output_path)
    except Exception as e:
        console.print(f"[bold red]Error generating graph report:[/bold red] {e}")
