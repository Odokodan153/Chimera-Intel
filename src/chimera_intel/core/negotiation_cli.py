import typer
from rich.console import Console
from rich.table import Table
import numpy as np
from . import data_ingestion
from .schemas import Counterparty, MarketIndicator
from .negotiation_rl_env import NegotiationEnv
from .negotiation_rl_agent import QLearningAgent

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
    env = NegotiationEnv()
    agent = QLearningAgent(action_space_n=env.action_space_n)

    console.print(
        f"[bold yellow]Starting RL agent training for {episodes} episodes...[/bold yellow]"
    )

    for episode in range(episodes):
        # Simplified simulation loop for training

        history = [
            {
                "sender_id": "them",
                "analysis": {
                    "offer_amount": np.random.randint(5000, 15000),
                    "tone_score": np.random.uniform(-1, 1),
                    "intent": "offer",
                },
            }
        ]
        state = env.get_state_from_history(history)

        done = False
        while not done:
            action = agent.choose_action(state)

            # Simulate a response and get reward

            reward = env.get_reward(history, action)

            # Simulate next state

            new_offer = (
                state[0] * np.random.uniform(0.9, 1.1) if action == 2 else state[0]
            )
            new_sentiment = state[2] + np.random.uniform(-0.2, 0.2)
            history.append(
                {
                    "sender_id": "ai_negotiator",
                    "analysis": {
                        "offer_amount": new_offer,
                        "tone_score": new_sentiment,
                        "intent": "offer",
                    },
                }
            )
            next_state = env.get_state_from_history(history)

            agent.update_q_table(state, action, reward, next_state)
            state = next_state

            # Check for terminal conditions

            if np.random.rand() < 0.1:  # 10% chance of random acceptance/rejection
                history.append(
                    {
                        "analysis": {
                            "intent": (
                                "acceptance" if np.random.rand() < 0.5 else "rejection"
                            )
                        }
                    }
                )
                reward = env.get_reward(history, action)
                agent.update_q_table(state, action, reward, next_state)  # Final update
                done = True
            elif len(history) > 20:  # Timeout
                done = True
    agent.save_model(output_path)
    console.print(
        f"[bold green]Training complete! Model saved to {output_path}[/bold green]"
    )


if __name__ == "__main__":
    negotiation_app()
