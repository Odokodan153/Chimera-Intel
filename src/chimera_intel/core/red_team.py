"""
The Red Team: An Adversarial Simulation & Strategy Validation Engine for Chimera Intel.
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

red_team_app = typer.Typer(
    name="red-team",
    help="Runs adversarial simulations to test defensive strategies.",
)

@red_team_app.command("simulate", help="Simulate a realistic adversarial campaign against a project's attack surface.")
def simulate(
    project: Annotated[str, typer.Option("--project", "-p", help="The project whose assets will be the target of the simulation.", prompt=True)],
    adversary: Annotated[str, typer.Option("--adversary", "-a", help="The threat actor to simulate (e.g., 'FIN7', 'APT29').", prompt=True)],
):
    """
    Simulates a realistic adversarial campaign against your organization's own
    attack surface, allowing you to test defensive strategies and identify
    weaknesses before a real attacker does.
    """
    console.print(f"Initiating Red Team simulation for project '[bold yellow]{project}[/bold yellow]'...")
    console.print(f"Adversary Profile: [bold red]{adversary}[/bold red]")

    try:
        db = next(get_db())
        scans = db.query(Scans).filter(Scans.project_name == project).all()
        if not scans:
            console.print(f"[bold red]Error:[/bold red] No assets found for project '{project}'. Cannot run simulation.")
            raise typer.Exit(code=1)

        # Synthesize all collected asset data for the project
        asset_summary = "\n".join([ScanModel.model_validate(s).model_dump_json(indent=2) for s in scans])

        # Construct the detailed prompt for the AI Red Team Agent
        prompt = (
            f"You are an AI-powered Red Team agent. Your mission is to simulate an attack campaign against the assets of project '{project}'. "
            f"You will adopt the persona and known tactics of the threat actor group: **{adversary}**.\n\n"
            "Your simulation must be structured as a step-by-step campaign, referencing specific MITRE ATT&CK techniques (e.g., 'T1566.001 - Spearphishing Attachment') for each action. "
            "Your goal is to achieve a common objective for this threat actor, such as data exfiltration for financial gain or establishing persistent access.\n\n"
            f"Here is the list of known assets for the target project:\n---\n{asset_summary}\n---\n\n"
            "Based on these assets and your knowledge of the adversary, generate a realistic, multi-stage attack plan. For each stage, describe the action, the target asset, and the specific ATT&CK technique used."
        )

        # Use the AI to generate the simulation
        simulation_result = perform_generative_task(prompt)

        console.print(Panel(
            simulation_result,
            title=f"[bold red]Red Team Simulation: {adversary} Campaign[/bold red]",
            border_style="red"
        ))

    except Exception as e:
        console.print(f"[bold red]An error occurred during the Red Team simulation:[/bold red] {e}")
        raise typer.Exit(code=1)