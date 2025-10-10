import numpy as np
import pickle
from typing import Dict, Any


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
        ]

        self.q_table = np.zeros((state_bins, state_bins, state_bins, action_space_n))

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
        with open(path, "wb") as f:
            pickle.dump(self.q_table, f)

    def load_model(self, path: str):
        with open(path, "rb") as f:
            self.q_table = pickle.load(f)
