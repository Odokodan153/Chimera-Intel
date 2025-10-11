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
        history = []
        state = env.get_state_from_history(history)
        done = False
        total_reward = 0

        while not done:
            action = agent.choose_action(state)

            # Low Priority: Use a deterministic opponent for reproducible training.

            if deterministic_opponent:
                opponent_response = {
                    "sender_id": "them",
                    "content": "I can offer a 10% reduction.",
                    "analysis": {
                        "intent": "offer",
                        "sentiment": "neutral",
                        "offer_amount": 11000,  # Example fixed offer
                    },
                }
            else:
                # In a real scenario, the opponent's response would be generated here.
                # For now, we'll simulate a simple response.

                opponent_response = {
                    "sender_id": "them",
                    "content": "That's an interesting offer. Let me consider it.",
                    "analysis": {
                        "intent": "neutral",
                        "sentiment": "neutral",
                        "offer_amount": np.random.uniform(7000, 13000),
                    },
                }
            history.append(opponent_response)

            reward = env.get_reward(history, action)
            next_state = env.get_state_from_history(history)
            done = env.is_done(history)

            agent.update_q_values(state, action, reward, next_state, done)
            state = next_state
            total_reward += reward

            # Log the step for analytics

            training_logs.append(
                {
                    "episode": episode,
                    "turn": len(history),
                    "state": state.tolist(),
                    "action": action,
                    "reward": reward,
                    "total_reward": total_reward,
                    "epsilon": agent.epsilon,
                }
            )
        if (episode + 1) % 100 == 0:
            logging.info(
                f"Episode {episode + 1}/{episodes} | Total Reward: {total_reward} | Epsilon: {agent.epsilon:.4f}"
            )
    with open(log_file, "w") as f:
        json.dump(training_logs, f, indent=4)
    logging.info(f"Training logs saved to {log_file}")


# High Priority: Splitting Training and Inference


def run_training_mode():
    """
    Runs the negotiation agent in training mode.
    """
    logging.info("--- Running in Training Mode ---")
    # In training mode, we use the MockLLMInterface to avoid API calls.
    # Medium Priority: Write unit tests for the MockLLMInterface.

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
        agent.epsilon = 0  # No exploration in inference mode
        logging.info("Successfully loaded pre-trained model.")
    except FileNotFoundError:
        logging.warning("No pre-trained model found. Using a new agent.")
    # The rest of the inference logic would go here, similar to the original `run_simulation`.
    # This would involve interacting with a user or another AI in real-time.


if __name__ == "__main__":
    # Example of how to switch between modes

    TRAINING = True
    if TRAINING:
        run_training_mode()
    else:
        run_inference_mode()
