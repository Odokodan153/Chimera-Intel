import typer
import json
from reportlab.platypus import (
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
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
from typing import Dict, Any, List, Optional
import logging
import os

# Import the global CONFIG object to access customization settings


from .config_loader import CONFIG

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

        # Add logo if the path is specified in config.yaml and the file exists

        logo_path = CONFIG.reporting.pdf.logo_path
        if logo_path and os.path.exists(logo_path):
            try:
                logo = Image(logo_path, width=2 * inch, height=2 * inch)
                logo.hAlign = "CENTER"
                story.append(logo)
                story.append(Spacer(1, 0.25 * inch))
            except Exception as e:
                logger.warning(f"Could not load logo image from {logo_path}: {e}")
        # Use the custom title from the loaded config.yaml

        story.append(Paragraph(CONFIG.reporting.pdf.title_text, styles["h1"]))
        story.append(Paragraph("Intelligence Report", styles["h2"]))
        target = json_data.get("domain") or json_data.get("company", "Unknown Target")
        story.append(Paragraph(f"Target: {target}", styles["h3"]))
        story.append(Spacer(1, 0.5 * inch))

        # --- Report Content ---
        # (The logic for generating the main content remains the same)

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
                        # Handle list of dictionaries (like subdomains)

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
                        # Handle simple key-value pairs

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
        # --- Build the PDF with the custom footer ---

        frame = Frame(
            doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="normal"
        )
        template = PageTemplate(id="main_template", frames=[frame], onPage=footer)
        doc.addPageTemplates([template])

        doc.build(story)
        logger.info("Successfully generated PDF report at: %s", output_path)
    except Exception as e:
        logger.error("An error occurred during PDF generation: %s", e, exc_info=True)


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
    # Determine the output path

    if not output_file:
        target_name = data.get("domain") or data.get("company", "report")
        output_path = f"{target_name.replace('.', '_')}.pdf"
    else:
        output_path = output_file
    # Generate the report

    generate_pdf_report(data, output_path)
