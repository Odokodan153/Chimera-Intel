import numpy as np
import pickle
from typing import Dict, Any, List
import json
import logging
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam

# --- Local Imports ---


from .llm_interface import LLMInterface
from .ethical_guardrails import EthicalFramework
from .cultural_intelligence import get_cultural_profile

# --- New QLearningAgent with Neural Network ---


class QLearningAgent:
    """
    A Q-learning agent that uses a neural network for function approximation.
    """

    def __init__(
        self,
        state_size: int = 5,
        action_space_n: int = 3,
        learning_rate: float = 0.001,
        discount_factor: float = 0.9,
        exploration_rate: float = 1.0,
        min_exploration_rate: float = 0.01,
        exploration_decay_rate: float = 0.995,
        use_exponential_decay: bool = False,
    ):
        """
        Initializes the Q-learning agent with a neural network.
        """
        self.state_size = state_size
        self.action_space_n = action_space_n
        self.lr = learning_rate
        self.gamma = discount_factor
        self.epsilon = exploration_rate
        self.min_epsilon = min_exploration_rate
        self.epsilon_decay = exploration_decay_rate
        self.use_exponential_decay = use_exponential_decay
        self.model = self._build_model()

    def _build_model(self):
        """Builds a simple neural network for Q-value approximation."""
        model = Sequential()
        model.add(Dense(24, input_dim=self.state_size, activation="relu"))
        model.add(Dense(24, activation="relu"))
        model.add(Dense(self.action_space_n, activation="linear"))
        model.compile(loss="mse", optimizer=Adam(learning_rate=self.lr))
        return model

    def choose_action(self, state: np.ndarray) -> int:
        """Chooses an action using an epsilon-greedy policy."""
        if np.random.rand() <= self.epsilon:
            return np.random.choice(self.action_space_n)
        state = np.reshape(state, [1, self.state_size])
        act_values = self.model.predict(state)
        return np.argmax(act_values[0])

    def update_q_values(
        self,
        state: np.ndarray,
        action: int,
        reward: float,
        next_state: np.ndarray,
        done: bool,
    ):
        """Updates the Q-values using the Bellman equation."""
        state = np.reshape(state, [1, self.state_size])
        next_state = np.reshape(next_state, [1, self.state_size])
        target = reward
        if not done:
            target = reward + self.gamma * np.amax(self.model.predict(next_state)[0])
        target_f = self.model.predict(state)
        target_f[0][action] = target
        self.model.fit(state, target_f, epochs=1, verbose=0)

        if self.epsilon > self.min_epsilon:
            if self.use_exponential_decay:
                # Low Priority: Experiment with adaptive decay schedules.
                self.epsilon = self.min_epsilon + (
                    self.epsilon - self.min_epsilon
                ) * np.exp(-self.epsilon_decay)
            else:
                self.epsilon *= self.epsilon_decay

    def save_model(self, path: str):
        """Saves the model weights to a file."""
        self.model.save_weights(path)

    def load_model(self, path: str):
        """Loads model weights from a file."""
        self.model.load_weights(path)


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

        # Medium Priority: Refactor the LLMInterface to use asynchronous calls (e.g., httpx, aiohttp).
        llm_output = self.llm.generate_message(
            prompt, system_role="You are a master negotiator in a simulation."
        )

        message_content = llm_output.get("message", "")
        violations = self.ethics.check_message(message_content)
        if violations:
            llm_output["ethical_violations"] = [v["violation"] for v in violations]

            llm_output[
                "message"
            ] += f"\n\n[SYSTEM WARNING: Potential ethical issues detected: {', '.join(llm_output['ethical_violations'])}]"
        return llm_output