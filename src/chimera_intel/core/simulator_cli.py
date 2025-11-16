"""
CLI for the negotiation simulator.
"""

import typer
from rich.console import Console
from rich.panel import Panel
from .negotiation_simulator import get_personas

console = Console()
simulator_app = typer.Typer(help="Train your negotiation skills against AI personas.")


@simulator_app.command("start")
def start_simulation(
    persona_name: str = typer.Argument(
        "cooperative",
        help="The persona to negotiate against (cooperative, aggressive, analytical).",
    )
):
    """
    Starts an interactive negotiation simulation with a chosen AI persona.
    """
    personas = get_personas()
    persona = personas.get(persona_name.lower())

    if not persona:
        console.print(
            f"[bold red]Error: Persona '{persona_name}' not found.[/bold red]"
        )
        return
    console.print(
        Panel(
            f"[bold]Negotiating with: {persona.name}[/bold]\n{persona.description}",
            title="Simulation Started",
            border_style="green",
        )
    )

    history = []
    while True:
        user_input = console.input("[bold yellow]Your Message: [/bold yellow]")
        if user_input.lower() in ["exit", "quit"]:
            break
        history.append({"sender_id": "user", "content": user_input})
        response_data = persona.generate_response(user_input, history)
        history.append(
            {"sender_id": "ai", "content": response_data["persona_response"]}
        )

        console.print(
            f"[cyan]{persona.name}:[/cyan] {response_data['persona_response']}"
        )
        console.print(
            f"[dim]Tactic: {response_data['tactic']} | Intent Detected: {response_data['analysis']['intent']}[/dim]\n"
        )


if __name__ == "__main__":
    simulator_app()
