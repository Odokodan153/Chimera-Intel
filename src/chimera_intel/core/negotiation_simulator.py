import json
import logging
import numpy as np
from typing import Dict, Any

from .negotiation_rl_agent import QLearningAgent
from .negotiation_rl_env import NegotiationEnv
from .llm_interface import MockLLMInterface

# High Priority: Comprehensive Logging for Analytics


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
        agent.clear_prediction_cache()
        history = []
        state = env.get_state_from_history(history)
        done = False
        total_reward = 0
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
                agent.update_q_values(state, action, reward, next_state, done)
            except Exception as e:
                logging.error(f"Error in update_q_values: {e}")
                break  # End episode on error
            state = next_state
            total_reward += reward
            turn += 1
        agent.decay_epsilon(episode)

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
    agent = QLearningAgent(use_exponential_decay=True)
    env = NegotiationEnv()
    train_rl_agent(agent, env, episodes=500, deterministic_opponent=True)
    agent.save_model("negotiation_rl_model.h5")
    logging.info("Training complete and model saved.")


def run_inference_mode(use_llm: bool = False):
    """
    Runs the negotiation agent in inference mode.
    """
    logging.info("--- Running in Inference Mode ---")
    agent = QLearningAgent()
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
