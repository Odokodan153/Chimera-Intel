import random
import json
import torch
import torch.optim as optim
import torch.nn.functional as F
from .llm_interface import LLMInterface
from .ethical_guardrails import EthicalFramework
from .cultural_intelligence import get_cultural_profile
from .dqn_model import DQN
import numpy as np


class QLearningAgent:
    def __init__(
        self, action_space_n, learning_rate=0.1, discount_factor=0.9, epsilon=0.1
    ):
        self.action_space_n = action_space_n
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.epsilon = epsilon
        self.q_table = {}

    def choose_action(self, state):
        state_tuple = tuple(sorted(state.items()))
        if random.uniform(0, 1) < self.epsilon or state_tuple not in self.q_table:
            return random.randint(0, self.action_space_n - 1)
        return self.q_table[state_tuple].index(max(self.q_table[state_tuple]))

    def learn(self, state, action, reward, next_state):
        state_tuple = tuple(sorted(state.items()))
        next_state_tuple = tuple(sorted(next_state.items()))
        if state_tuple not in self.q_table:
            self.q_table[state_tuple] = [0] * self.action_space_n
        if next_state_tuple not in self.q_table:
            self.q_table[next_state_tuple] = [0] * self.action_space_n
        old_value = self.q_table[state_tuple][action]
        next_max = max(self.q_table[next_state_tuple])

        new_value = (1 - self.learning_rate) * old_value + self.learning_rate * (
            reward + self.discount_factor * next_max
        )
        self.q_table[state_tuple][action] = new_value

    def load_model(self, path):
        with open(path, "r") as f:
            self.q_table = json.load(f)

    def save_model(self, path):
        with open(path, "w") as f:
            json.dump(self.q_table, f)


class QLearningLLMAgent:
    def __init__(
        self, llm: LLMInterface, ethics: EthicalFramework, db_params, action_space_n
    ):
        self.llm = llm
        self.ethics = ethics
        self.db_params = db_params
        self.action_space_n = action_space_n
        # Parameters for DQN

        self.batch_size = 128
        self.gamma = 0.99
        self.eps_start = 0.9
        self.eps_end = 0.05
        self.eps_decay = 1000
        self.tau = 0.005
        self.lr = 1e-4

        # We need to define the state size based on the features we extract
        # For now, let's assume a fixed size based on our state representation

        n_observations = 4  # sentiment, tactics, turn, offer presence
        self.policy_net = DQN(n_observations, action_space_n)
        self.target_net = DQN(n_observations, action_space_n)
        self.target_net.load_state_dict(self.policy_net.state_dict())

        self.optimizer = optim.AdamW(
            self.policy_net.parameters(), lr=self.lr, amsgrad=True
        )
        self.memory = []
        self.steps_done = 0

    def _state_to_tensor(self, state):
        # Convert state dictionary to a tensor

        sentiment_map = {"positive": 1, "neutral": 0, "negative": -1}
        sentiment = sentiment_map.get(state.get("last_message_sentiment"), 0)
        num_tactics = len(state.get("detected_tactics_in_last_message", []))
        turn_number = state.get("negotiation_turn_number", 0)
        offer_present = (
            1 if "offer" in state.get("last_message_content", "").lower() else 0
        )
        return torch.tensor(
            [[sentiment, num_tactics, turn_number, offer_present]], dtype=torch.float32
        )

    def choose_action(self, state):
        sample = random.random()
        eps_threshold = self.eps_end + (self.eps_start - self.eps_end) * np.exp(
            -1.0 * self.steps_done / self.eps_decay
        )
        self.steps_done += 1
        if sample > eps_threshold:
            with torch.no_grad():
                state_tensor = self._state_to_tensor(state)
                return self.policy_net(state_tensor).max(1)[1].view(1, 1)
        else:
            return torch.tensor(
                [[random.randrange(self.action_space_n)]], dtype=torch.long
            )

    async def generate_negotiation_message_async(
        self, state, counterparty_country_code=None
    ):
        cultural_profile = (
            get_cultural_profile(counterparty_country_code)
            if counterparty_country_code
            else {}
        )
        prompt = self._construct_prompt(state, cultural_profile)
        response = await self.llm.generate_message_async(prompt)
        # Ethical check

        violations = self.ethics.check_message(response)
        if violations:
            # Handle violations - for now, just log and return a safe response

            return "I need to reconsider my approach. Let's try to find a mutually agreeable solution."
        return response

    def _construct_prompt(self, state, cultural_profile):
        prompt = (
            "You are a negotiation agent. Based on the following state, generate a response.\n"
            f"State: {json.dumps(state, indent=2)}\n"
        )
        if cultural_profile:
            prompt += f"Consider the following cultural profile for your counterparty: {json.dumps(cultural_profile, indent=2)}\n"
        prompt += (
            "Your response should be strategic and aim to achieve a favorable outcome."
        )
        return prompt

    def optimize_model(self):
        if len(self.memory) < self.batch_size:
            return
        transitions = random.sample(self.memory, self.batch_size)
        # This is where you'd implement the DQN learning step (e.g., Bellman equation)
        # For brevity, this part is simplified

        pass

    def load_model(self, path):
        self.policy_net.load_state_dict(torch.load(path))
        self.target_net.load_state_dict(torch.load(path))

    def save_model(self, path):
        torch.save(self.policy_net.state_dict(), path)
