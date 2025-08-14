import typer
import json
from rich.console import Console
from rich.panel import Panel
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
from typing import Dict, Any

console = Console()

def generate_pdf_report(json_data: Dict[str, Any], output_path: str) -> None:
    """
    Generates a professional PDF report from a JSON scan result.

    This function uses the ReportLab library to construct a PDF document. It iterates
    through the modules and sections of the input JSON data, creating titles,
    paragraphs, and tables for each part.

    Args:
        json_data (Dict[str, Any]): The loaded JSON data from a scan.
        output_path (str): The path where the generated PDF file will be saved.
    """
    try:
        doc = SimpleDocTemplate(output_path)
        styles = getSampleStyleSheet()
        story = []

        # --- Title Page ---
        story.append(Paragraph("Chimera Intel", styles['h1']))
        story.append(Paragraph("Intelligence Report", styles['h2']))
        target = json_data.get('domain') or json_data.get('company', 'Unknown Target')
        story.append(Paragraph(f"Target: {target}", styles['h3']))
        story.append(Spacer(1, 0.5 * inch))

        # --- Report Content ---
        # Iterate through the main keys of the JSON file (e.g., 'footprint', 'web_analysis')
        for module_name, module_data in json_data.items():
            if isinstance(module_data, dict):
                story.append(Paragraph(module_name.replace('_', ' ').title(), styles['h2']))
                
                for section_name, section_data in module_data.items():
                    # Skip non-data sections
                    if not isinstance(section_data, dict):
                        continue
                        
                    story.append(Paragraph(section_name.replace('_', ' ').title(), styles['h3']))
                    
                    # Create a table for the key-value data
                    table_data = []
                    # Handle special case for scored results (like subdomains/tech)
                    if 'results' in section_data and isinstance(section_data['results'], list):
                        table_data = [["Item", "Confidence", "Sources"]]
                        for item in section_data['results']:
                            item_name = item.get('domain') or item.get('technology', 'N/A')
                            confidence = item.get('confidence', 'N/A')
                            sources = ', '.join(item.get('sources', []))
                            table_data.append([item_name, confidence, sources])
                    else:
                        table_data = [[key, str(value)] for key, value in section_data.items()]

                    if table_data:
                        t = Table(table_data, colWidths=[2 * inch, 3.5 * inch], repeatRows=1)
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black),
                            ('WORDWRAP', (0, 0), (-1, -1), 'CJK')
                        ]))
                        story.append(t)
                    
                    story.append(Spacer(1, 0.2 * inch))

        # Build the PDF
        doc.build(story)
        console.print(f"[bold green]Successfully generated PDF report at:[/] {output_path}")

    except Exception as e:
        console.print(f"[bold red]PDF Generation Error:[/bold red] {e}")


# --- Typer CLI Application ---

report_app = typer.Typer()

@report_app.command("pdf")
def create_pdf_report(
    json_file: str = typer.Argument(..., help="Path to the JSON scan result file."),
    output_file: str = typer.Option(None, "--output", "-o", help="Path to save the PDF report. Defaults to '<target>.pdf'.")
):
    """
    Creates a PDF report from a saved JSON scan file.
    """
    console.print(Panel(f"[bold blue]Generating PDF Report from:[/] {json_file}", title="Chimera Intel | Reporter", border_style="blue"))

    # Load the JSON data from the input file
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/] Input file not found at '{json_file}'")
        raise typer.Exit(code=1)
    except json.JSONDecodeError:
        console.print(f"[bold red]Error:[/] Invalid JSON in file '{json_file}'")
        raise typer.Exit(code=1)

    # Determine the output path
    if not output_file:
        target_name = data.get('domain') or data.get('company', 'report')
        output_path = f"{target_name.replace('.', '_')}.pdf"
    else:
        output_path = output_file

    # Generate the report
    generate_pdf_report(data, output_path)