import torch  # <-- Add this import
import torch.nn as nn
import torch.nn.functional as F
import random  # <-- Add this import


class DQN(nn.Module):
    """
    A simple Deep Q-Network (DQN) for the negotiation agent.
    """

    def __init__(self, n_observations, n_actions):
        super(DQN, self).__init__()
        self.layer1 = nn.Linear(n_observations, 128)
        self.layer2 = nn.Linear(128, 128)
        self.layer3 = nn.Linear(128, n_actions)
        self.n_actions = n_actions  # <-- Store n_actions

    def forward(self, x):
        x = F.relu(self.layer1(x))
        x = F.relu(self.layer2(x))
        return self.layer3(x)

    # --- FIX: Add the missing select_action method ---
    def select_action(self, state, eps_threshold):
        """
        Selects an action using an epsilon-greedy policy.
        """
        sample = random.random()
        if sample > eps_threshold:
            # Greedy action: exploit the learned policy
            with torch.no_grad():
                # self.forward(state) computes Q-values
                # .max(1)[1] gets the index of the highest Q-value
                # .view(1) ensures it's a tensor of shape [1]
                return self.forward(state).max(1)[1].view(1)
        else:
            # Random action: explore
            # Get device from state to ensure tensor is on same device
            device = state.device if state.is_cuda else "cpu"
            return torch.randint(
                0, self.n_actions, (1,), dtype=torch.long, device=device
            )
