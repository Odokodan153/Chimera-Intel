import typer
import os
import json
import google.generativeai as genai
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from chimera_intel.core.database import get_aggregated_data_for_target

console = Console()

def generate_strategic_profile(aggregated_data: dict, api_key: str) -> str:
    """Uses a Generative AI model to create a high-level strategic profile of a company."""
    if not api_key:
        return "Error: GOOGLE_API_KEY not found in .env file."
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-pro')
    data_str = json.dumps(aggregated_data, indent=2)
    prompt = f"""
    As an expert business intelligence analyst, your task is to synthesize the following OSINT data into a high-level strategic profile of the target company.
    Based ONLY on the provided data, provide a concise analysis covering these points in Markdown format:
    1.  **Marketing & Sales Strategy:** What is their likely go-to-market strategy? B2C or B2B?
    2.  **Technology & Innovation Strategy:** Are they a technology leader, a fast follower, or lagging?
    3.  **Expansion & Growth Strategy:** Are there signals of expansion or new product launches?
    4.  **Overall Summary:** A concluding paragraph on their market position.

    OSINT DATA:
    ```json
    {data_str}
    ```
    """
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"An error occurred with the Google AI API: {e}"

strategy_app = typer.Typer()

@strategy_app.command("run")
def run_strategy_analysis(target: str = typer.Argument(..., help="The target company to analyze.")):
    """Generates an AI-powered strategic profile of a competitor."""
    console.print(Panel(f"[bold cyan]Generating Strategic Profile For:[/] {target}", title="Chimera Intel | Strategy Mapper", border_style="cyan"))
    console.print(f" [dim]>[/dim] [dim]Aggregating historical data for '{target}'...[/dim]")
    aggregated_data = get_aggregated_data_for_target(target)
    if not aggregated_data:
        raise typer.Exit()
    console.print(f" [dim]>[/dim] [dim]Submitting data to AI strategist for analysis...[/dim]")
    api_key = os.getenv("GOOGLE_API_KEY")
    strategic_profile = generate_strategic_profile(aggregated_data, api_key)
    console.print("\n--- [bold]Automated Strategic Profile[/bold] ---\n")
    console.print(Markdown(strategic_profile))