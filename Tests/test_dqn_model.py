import pytest
import torch
import torch.nn as nn
from unittest.mock import patch

# Adjust the import path based on your project structure
from chimera_intel.core.dqn_model import DQN


@pytest.fixture
def model():
    """Fixture to create a default DQN model."""
    state_dim = 4
    action_dim = 2
    return DQN(state_dim, action_dim)


def test_model_creation(model):
    """Tests if the model is created with the correct layers."""
    assert isinstance(model, nn.Module)
    assert len(list(model.children())) > 0  # Check if it has layers

    # FIX: Access attributes directly instead of a 'layers' list
    layer1 = model.layer1
    assert isinstance(layer1, nn.Linear)

    # FIX: Access attributes directly
    layer_last = model.layer3
    assert isinstance(layer_last, nn.Linear)


def test_forward_pass(model):
    """Tests the forward pass with a sample tensor."""
    state_dim = 4
    batch_size = 10

    # Create a random batch of states
    # Requires grad=True to simulate a training step input
    sample_input = torch.randn(batch_size, state_dim)

    output = model(sample_input)

    # Check output shape
    action_dim = 2
    assert output.shape == (batch_size, action_dim)

    # Check output type
    assert output.dtype == torch.float32


def test_forward_pass_single_item(model):
    """Tests the forward pass with a single state tensor."""
    state_dim = 4

    # Create a single random state
    sample_input = torch.randn(1, state_dim)

    output = model(sample_input)

    # Check output shape
    action_dim = 2
    assert output.shape == (1, action_dim)


@patch("torch.rand")
@patch("random.random")
def test_select_action_greedy(mock_random, mock_torch_rand, model):
    """Tests that the greedy action (highest Q-value) is selected when eps_threshold is low."""
    mock_random.return_value = 1.0  # Force greedy selection (1.0 > eps_threshold)

    state_dim = 4
    state = torch.randn(1, state_dim)  # Example state

    # Mock the model's forward pass to return predictable Q-values
    # Action 1 (index 1) has the highest value (10.0)
    with patch.object(
        model, "forward", return_value=torch.tensor([[1.0, 10.0]])
    ) as mock_forward:
        action = model.select_action(state, eps_threshold=0.1)

        mock_forward.assert_called_once_with(state)

        # Check that the action with the highest Q-value (index 1) was selected
        assert action.item() == 1


@patch("random.random")
@patch("torch.randint")
def test_select_action_random(mock_torch_randint, mock_random, model):
    """Tests that a random action is selected when eps_threshold is high."""
    mock_random.return_value = 0.0  # Force random selection (0.0 <= eps_threshold)

    # Mock the random integer generation to return a predictable "random" action (e.g., action 0)
    action_dim = 2
    mock_torch_randint.return_value = torch.tensor(
        [0], dtype=torch.long
    )  # Mocked random action

    state_dim = 4
    state = torch.randn(1, state_dim)  # Example state

    # Mock the model's forward pass (it shouldn't be used for argmax, but will be called)
    with patch.object(
        model, "forward", return_value=torch.tensor([[1.0, 10.0]])
    ) as mock_forward:
        action = model.select_action(state, eps_threshold=0.9)  # High epsilon

        # Ensure the model's forward pass is NOT used to determine the action
        mock_forward.assert_not_called()

        # Check that the mocked random action (index 0) was selected
        mock_torch_randint.assert_called_once_with(
            0, action_dim, (1,), dtype=torch.long, device="cpu"
        )
        assert action.item() == 0


def test_model_to_device(model):
    """Checks if the model can be moved to a device (e.g., 'cpu')."""
    if torch.cuda.is_available():
        device = torch.device("cuda")
    else:
        device = torch.device("cpu")

    model.to(device)

    # Check if a parameter is on the correct device
    assert next(model.parameters()).device.type == device.type
