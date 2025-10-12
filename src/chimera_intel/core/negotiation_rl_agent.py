import random
import json
import torch
import torch.optim as optim
from .llm_interface import LLMInterface, MockLLMInterface
from .ethical_guardrails import EthicalFramework
from .cultural_intelligence import get_cultural_profile
from .dqn_model import DQN
import numpy as np
from collections import namedtuple
import torch.nn as nn
from typing import Union, List

# Define the Transition named tuple at the module level

Transition = namedtuple("Transition", ("state", "action", "next_state", "reward"))


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
        self,
        llm: Union[LLMInterface, MockLLMInterface],
        ethics: EthicalFramework,
        db_params,
        action_space_n,
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
        self.device = next(self.policy_net.parameters()).device

        self.optimizer = optim.AdamW(
            self.policy_net.parameters(), lr=self.lr, amsgrad=True
        )
        self.memory: List[Transition] = []
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
            [[sentiment, num_tactics, turn_number, offer_present]],
            dtype=torch.float32,
            device=self.device,
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
                [[random.randrange(self.action_space_n)]],
                dtype=torch.long,
                device=self.device,
            )

    def generate_negotiation_message(
        self, state, history, counterparty_country_code=None, persona=None
    ):
        cultural_profile = (
            get_cultural_profile(counterparty_country_code)
            if counterparty_country_code
            else {}
        )
        prompt = self._construct_prompt(state, cultural_profile)
        response = self.llm.generate_message(prompt)
        # Ethical check

        violations = self.ethics.check_message(response)
        if violations:
            # Handle violations - for now, just log and return a safe response

            return {
                "tactic": "error",
                "message": "I need to reconsider my approach. Let's try to find a mutually agreeable solution.",
                "confidence": 0.0,
                "ethical_violations": violations,
            }
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
        # Transpose the batch (see https://stackoverflow.com/a/19343/3343043 for
        # detailed explanation). This converts batch-array of Transitions
        # to Transition of batch-arrays.

        batch = Transition(*zip(*transitions))

        # Compute a mask of non-final states and concatenate the batch elements
        # (a final state would've been the one after which simulation ended)

        non_final_mask = torch.tensor(
            tuple(map(lambda s: s is not None, batch.next_state)),
            device=self.device,
            dtype=torch.bool,
        )
        non_final_next_states = torch.cat(
            [s for s in batch.next_state if s is not None]
        )
        state_batch = torch.cat(batch.state)
        action_batch = torch.cat(batch.action)
        reward_batch = torch.cat(batch.reward)

        # Compute Q(s_t, a) - the model computes Q(s_t), then we select the
        # columns of actions taken. These are the actions which would've been taken
        # for each batch state according to policy_net

        state_action_values = self.policy_net(state_batch).gather(1, action_batch)

        # Compute V(s_{t+1}) for all next states.
        # Expected values of actions for non_final_next_states are computed based
        # on the "older" target_net; selecting their best reward with max(1)[0].
        # This is merged based on the mask, such that we'll have either the expected
        # state value or 0 in case of a final state.

        next_state_values = torch.zeros(self.batch_size, device=self.device)
        with torch.no_grad():
            next_state_values[non_final_mask] = self.target_net(
                non_final_next_states
            ).max(1)[0]
        # Compute the expected Q values

        expected_state_action_values = (next_state_values * self.gamma) + reward_batch

        # Compute Huber loss

        criterion = nn.SmoothL1Loss()
        loss = criterion(state_action_values, expected_state_action_values.unsqueeze(1))

        # Optimize the model

        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_value_(self.policy_net.parameters(), 100)
        self.optimizer.step()

    def load_model(self, path):
        self.policy_net.load_state_dict(torch.load(path))
        self.target_net.load_state_dict(torch.load(path))

    def save_model(self, path):
        torch.save(self.policy_net.state_dict(), path)
