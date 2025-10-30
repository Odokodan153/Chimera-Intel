import json
import logging
from collections import namedtuple
from typing import Any, Dict, List
import numpy as np

from .negotiation_rl_agent import QLearningAgent
from .negotiation_rl_env import NegotiationEnv

# High Priority: Comprehensive Logging for Analytics


Persona = namedtuple("Persona", ["name", "description", "generate_response"])


def get_personas():
    """
    Returns a dictionary of predefined negotiation personas.
    """

    def cooperative_response(user_input, history):
        return {
            "persona_response": "That's a reasonable point. I'm willing to work with you on this.",
            "tactic": "Acknowledge and Concede",
            "analysis": {"intent": "agreement"},
        }

    def aggressive_response(user_input, history):
        return {
            "persona_response": "I'm not going to waste time with that. Give me a better offer.",
            "tactic": "High-pressure",
            "analysis": {"intent": "demand"},
        }

    def analytical_response(user_input, history):
        return {
            "persona_response": "Let's look at the data. The market trends don't support that price.",
            "tactic": "Data-driven argument",
            "analysis": {"intent": "justification"},
        }

    return {
        "cooperative": Persona(
            name="Cooperative",
            description="Aims for a win-win outcome and is willing to make concessions.",
            generate_response=cooperative_response,
        ),
        "aggressive": Persona(
            name="Aggressive",
            description="Focuses on winning and may use pressure tactics.",
            generate_response=aggressive_response,
        ),
        "analytical": Persona(
            name="Analytical",
            description="Relies on data and logic to make their case.",
            generate_response=analytical_response,
        ),
    }


def train_rl_agent(
    agent: QLearningAgent,
    env: NegotiationEnv,
    episodes: int = 1000,
    log_file: str = "rl_training_log.json",
    deterministic_opponent: bool = False,
):
    """
    Trains the RL agent using a simulated environment.
    """
    training_logs = []
    for episode in range(episodes):
        history: List[Dict[str, Any]] = []
        state = env.get_state_from_history(history)
        done = False
        total_reward = 0.0
        turn = 0

        while not done:
            try:
                action = agent.choose_action(state)
            except Exception as e:
                logging.error(f"Error in choose_action: {e}")
                break  # End episode on error
            if deterministic_opponent:
                opponent_response = {
                    "sender_id": "them",
                    "content": "I can offer a 10% reduction.",
                    "analysis": {
                        "intent": "offer",
                        "sentiment": "neutral",
                        "tone_score": 0.0,
                        "offer_amount": 11000,
                    },
                }
            else:
                opponent_response = {
                    "sender_id": "them",
                    "content": "That's an interesting offer. Let me consider it.",
                    "analysis": {
                        "intent": "neutral",
                        "sentiment": "neutral",
                        "tone_score": 0.0,
                        "offer_amount": np.random.uniform(7000, 13000),
                    },
                }
            history.append(opponent_response)

            reward = env.get_reward(history, action)
            next_state = env.get_state_from_history(history)
            done = env.is_done(history)

            try:
                agent.learn(state, action, reward, next_state)
            except Exception as e:
                logging.error(f"Error in update_q_values: {e}")
                break  # End episode on error
            state = next_state
            total_reward += reward
            turn += 1
        training_logs.append(
            {
                "episode": episode,
                "total_reward": total_reward,
                "epsilon": agent.epsilon,
                "turns": turn,
                "final_intent": (
                    history[-1].get("analysis", {}).get("intent") if history else "N/A"
                ),
            }
        )

        if (episode + 1) % 100 == 0:
            logging.info(
                f"Episode {episode + 1}/{episodes} | Total Reward: {total_reward} | Epsilon: {agent.epsilon:.4f}"
            )
    with open(log_file, "w") as f:
        json.dump(training_logs, f, indent=4)
    logging.info(f"Training logs saved to {log_file}")


def run_training_mode():
    """
    Runs the negotiation agent in training mode.
    """
    logging.info("--- Running in Training Mode ---")
    agent = QLearningAgent(action_space_n=10)
    env = NegotiationEnv()
    train_rl_agent(agent, env, episodes=500, deterministic_opponent=True)
    agent.save_model("negotiation_rl_model.h5")
    logging.info("Training complete and model saved.")


def run_inference_mode(use_llm: bool = False):
    """
    Runs the negotiation agent in inference mode.
    """
    logging.info("--- Running in Inference Mode ---")
    agent = QLearningAgent(action_space_n=10)
    try:
        agent.load_model("negotiation_rl_model.h5")
        agent.epsilon = 0
        logging.info("Successfully loaded pre-trained model.")
    except (FileNotFoundError, IOError):
        logging.warning("No pre-trained model found. Using a new agent.")


if __name__ == "__main__":
    TRAINING = True
    if TRAINING:
        run_training_mode()
    else:
        run_inference_mode()
