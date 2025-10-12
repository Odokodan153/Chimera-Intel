import typer
from rich.console import Console
import numpy as np
from . import data_ingestion
from .schemas import Counterparty, MarketIndicator
from .negotiation_rl_env import NegotiationEnv
from .negotiation_rl_agent import QLearningAgent, QLearningLLMAgent
from .ethical_guardrails import EthicalFramework
from .llm_interface import LLMInterface, MockLLMInterface
from .negotiation_simulator import get_personas

console = Console()
negotiation_app = typer.Typer(help="Tools for AI-assisted negotiation.")


@negotiation_app.command("add-counterparty")
def add_counterparty_cli(
    name: str = typer.Option(..., "--name", "-n", help="Name of the counterparty."),
    industry: str = typer.Option(
        None, "--industry", "-i", help="Industry of the counterparty."
    ),
    country: str = typer.Option(
        None, "--country", "-c", help="Country of the counterparty."
    ),
):
    """Adds a new counterparty to the intelligence database."""
    counterparty = Counterparty(name=name, industry=industry, country=country)
    counterparty_id = data_ingestion.add_counterparty(counterparty)
    if counterparty_id:
        console.print(
            f"[bold green]Successfully added counterparty '{name}' with ID: {counterparty_id}[/bold green]"
        )


@negotiation_app.command("add-market-indicator")
def add_market_indicator_cli(
    name: str = typer.Option(
        ..., "--name", "-n", help="Name of the market indicator (e.g., 'S&P 500')."
    ),
    value: float = typer.Option(..., "--value", "-v", help="Value of the indicator."),
    source: str = typer.Option(
        ..., "--source", "-s", help="Source of the indicator (e.g., 'Yahoo Finance')."
    ),
):
    """Adds a new market indicator to the intelligence database."""
    indicator = MarketIndicator(name=name, value=value, source=source)
    indicator_id = data_ingestion.add_market_indicator(indicator)
    if indicator_id:
        console.print(
            f"[bold green]Successfully added market indicator '{name}' with ID: {indicator_id}[/bold green]"
        )


@negotiation_app.command("train-rl")
def train_rl_agent(
    episodes: int = typer.Option(
        10000, "--episodes", "-e", help="Number of simulation episodes to run."
    ),
    output_path: str = typer.Option(
        "negotiation_rl_model.pkl",
        "--output",
        "-o",
        help="Path to save the trained model.",
    ),
):
    """Trains the negotiation RL agent through simulation."""
    np.random.seed(42)  # for reproducibility
    env = NegotiationEnv()
    agent = QLearningAgent(action_space_n=env.action_space_n)

    console.print(
        f"[bold yellow]Starting RL agent training for {episodes} episodes...[/bold yellow]"
    )

    for episode in range(episodes):
        history = [
            {
                "sender_id": "them",
                "content": "Initial offer",
                "analysis": {
                    "offer_amount": np.random.randint(5000, 15000),
                    "tone_score": np.random.uniform(-0.5, 0.5),
                    "intent": "offer",
                },
            }
        ]
        state = env.get_state_from_history(history)
        done = False

        while not done:
            action = agent.choose_action(state)

            # Simulate environment response
            # In a real scenario, this would involve a more complex opponent model

            new_offer = state[1] * np.random.uniform(0.95, 1.05)
            new_sentiment = state[2] + np.random.uniform(-0.1, 0.1)

            history.append(
                {
                    "sender_id": "ai_negotiator",
                    "content": "AI's counter-offer",
                    "analysis": {
                        "offer_amount": new_offer,
                        "tone_score": new_sentiment,
                        "intent": "offer",
                    },
                }
            )

            next_state = env.get_state_from_history(history)
            reward = env.get_reward(history, action)
            agent.update_q_table(state, action, reward, next_state)
            state = next_state

            if env.is_done(history):
                done = True
    agent.save_model(output_path)
    console.print(
        f"[bold green]Training complete! Model saved to {output_path}[/bold green]"
    )


@negotiation_app.command("simulate-llm")
def simulate_llm_message(
    country: str = typer.Option(
        "US", "--country", "-c", help="Country code for cultural context."
    ),
    persona_name: str = typer.Option(
        "cooperative",
        "--persona",
        "-p",
        help="The negotiation persona to use (cooperative, aggressive, analytical).",
    ),
    use_mock: bool = typer.Option(
        False, "--mock", help="Use the mock LLM for testing to avoid API calls."
    ),
):
    """Generate a negotiation message using the LLM with a specific persona."""
    console.print(
        f"[bold yellow]Simulating LLM response for a '{persona_name}' persona targeting '{country}'...[/bold yellow]"
    )

    ethics = EthicalFramework()
    try:
        llm = MockLLMInterface() if use_mock else LLMInterface()
    except ValueError as e:
        console.print(f"[bold red]LLM Error:[/bold red] {e}")
        raise typer.Exit()
    personas = get_personas()
    persona = personas.get(persona_name.lower())
    if not persona:
        console.print(
            f"[bold red]Error:[/bold red] Persona '{persona_name}' not found."
        )
        raise typer.Exit()
    agent = QLearningLLMAgent(llm=llm, ethics=ethics, db_params={})

    # Create a realistic sample history for context

    history = [
        {
            "sender_id": "them",
            "content": "We were hoping for a price closer to $8,500.",
            "analysis": {"offer_amount": 8500, "tone_score": -0.2, "intent": "offer"},
        },
        {
            "sender_id": "ai_negotiator",
            "content": "I understand your position. $8,500 is a bit lower than we anticipated. Perhaps we can explore other terms?",
            "analysis": {
                "offer_amount": None,
                "tone_score": 0.1,
                "intent": "discussion",
            },
        },
    ]

    env = NegotiationEnv(opponent_persona=persona)
    state = env.get_state_from_history(history)

    # Generate the structured message

    llm_response = agent.generate_negotiation_message(state, history, country, persona)

    console.print("\n[bold cyan]-- LLM Structured Output --[/bold cyan]")
    console.print(f"[bold]Tactic:[/bold] {llm_response.get('tactic')}")
    console.print(f"[bold]Confidence:[/bold] {llm_response.get('confidence')}")
    if llm_response.get("ethical_violations"):
        console.print(
            f"[bold red]Ethical Violations:[/bold red] {llm_response['ethical_violations']}"
        )
    console.print("\n[bold cyan]-- Generated Message --[/bold cyan]")
    console.print(f"{llm_response.get('message')}")


if __name__ == "__main__":
    negotiation_app()
