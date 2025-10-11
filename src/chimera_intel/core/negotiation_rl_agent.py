import numpy as np
import pickle
from typing import Dict, Any, List
import json
import logging

# --- Local Imports ---

from .llm_interface import LLMInterface
from .ethical_guardrails import EthicalFramework
from .cultural_intelligence import get_cultural_profile

# --- Existing QLearningAgent class ---


class QLearningAgent:
    """
    A simple Q-learning agent for the negotiation task.
    It uses a Q-table to learn the optimal action for each state.
    """

    def __init__(
        self,
        state_bins: int = 10,
        action_space_n: int = 3,
        learning_rate: float = 0.1,
        discount_factor: float = 0.9,
        exploration_rate: float = 1.0,
        min_exploration_rate: float = 0.01,
        exploration_decay_rate: float = 0.995,
    ):
        """
        Initializes the Q-learning agent.
        """
        self.lr = learning_rate
        self.gamma = discount_factor
        self.epsilon = exploration_rate
        self.min_epsilon = min_exploration_rate
        self.epsilon_decay = exploration_decay_rate
        self.action_space_n = action_space_n
        self.state_bins = state_bins

        # Discretize the state space for the Q-table

        self.bins = [
            np.linspace(0, 20000, state_bins),  # Offer range
            np.linspace(0, 20000, state_bins),  # Offer range
            np.linspace(-1, 1, state_bins),  # Sentiment range
            np.linspace(-2, 2, state_bins),  # Sentiment trend
            np.linspace(0, 25, state_bins),  # Turn count
        ]
        self.q_table = np.zeros(tuple([state_bins] * len(self.bins) + [action_space_n]))

    def _discretize_state(self, state: np.ndarray) -> tuple:
        """Converts a continuous state vector into a discrete tuple for the Q-table."""
        discretized = [
            np.clip(np.digitize(state[i], self.bins[i]) - 1, 0, self.state_bins - 1)
            for i in range(len(state))
        ]
        return tuple(discretized)

    def choose_action(self, state: np.ndarray) -> int:
        """Chooses an action using an epsilon-greedy policy."""
        if np.random.uniform(0, 1) < self.epsilon:
            return np.random.choice(self.action_space_n)  # Explore
        else:
            discrete_state = self._discretize_state(state)
            return np.argmax(self.q_table[discrete_state])  # Exploit

    def update_q_table(
        self, state: np.ndarray, action: int, reward: float, next_state: np.ndarray
    ):
        """Updates the Q-table based on the Bellman equation."""
        discrete_state = self._discretize_state(state)
        next_discrete_state = self._discretize_state(next_state)

        old_value = self.q_table[discrete_state][action]
        next_max = np.max(self.q_table[next_discrete_state])

        new_value = (1 - self.lr) * old_value + self.lr * (
            reward + self.gamma * next_max
        )
        self.q_table[discrete_state][action] = new_value

        # Decay epsilon

        if self.epsilon > self.min_epsilon:
            self.epsilon *= self.epsilon_decay

    def save_model(self, path: str):
        """Saves the Q-table to a file."""
        with open(path, "wb") as f:
            pickle.dump(self.q_table, f)

    def load_model(self, path: str):
        """Loads a Q-table from a file."""
        with open(path, "rb") as f:
            self.q_table = pickle.load(f)


# --- New QLearningLLMAgent class ---


class QLearningLLMAgent(QLearningAgent):
    """
    An advanced Q-learning agent that integrates with an LLM for response generation
    and handles structured, contextual information.
    """

    def __init__(
        self,
        llm: LLMInterface,
        ethics: EthicalFramework,
        db_params: dict,
        *args,
        **kwargs,
    ):
        """
        Initializes the agent with LLM, ethics framework, and database parameters.
        """
        super().__init__(*args, **kwargs)
        self.llm = llm
        self.ethics = ethics
        self.db_params = db_params

    def generate_negotiation_message(
        self,
        state: np.ndarray,
        history: List[Dict[str, Any]],
        country_code: str,
        persona: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generates a culturally and persona-aware negotiation message using the LLM.
        """
        cultural_profile = get_cultural_profile(country_code)
        if not cultural_profile:
            cultural_profile = {
                "country_name": "Unknown",
                "directness": 5,
                "formality": 5,
            }
        # Provide the last 5 messages as context to the LLM

        conversation_history = "\n".join(
            [
                f"{msg.get('sender_id', 'unknown')}: {msg.get('content', '')}"
                for msg in history[-5:]
            ]
        )

        prompt = f"""
        You are an AI negotiating agent. Your current persona is '{persona.get('name', 'default')}'.
        Description of your persona: {persona.get('description', 'N/A')}

        You are negotiating with a counterpart from {cultural_profile.get('country_name', 'an unknown location')}.
        Their cultural profile suggests:
        - Directness (1-10): {cultural_profile.get('directness', 5)}
        - Formality (1-10): {cultural_profile.get('formality', 5)}

        Recent conversation history:
        {conversation_history}

        Current state vector (our avg offer, their avg offer, avg sentiment, sentiment trend, turn #):
        {state.tolist()}

        Based on all this information, determine the best tactic and generate a response.
        """

        llm_output = self.llm.generate_message(
            prompt, system_role="You are a master negotiator in a simulation."
        )

        # Perform ethical validation on the generated message

        message_content = llm_output.get("message", "")
        violations = self.ethics.check_message(message_content)
        if violations:
            llm_output["ethical_violations"] = [v["violation"] for v in violations]
            # Append a warning, but do not alter the core message to allow for analysis

            llm_output[
                "message"
            ] += f"\n\n[SYSTEM WARNING: Potential ethical issues detected: {', '.join(llm_output['ethical_violations'])}]"
        return llm_output
