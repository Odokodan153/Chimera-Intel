import unittest
import torch
from unittest.mock import patch, MagicMock, mock_open, ANY
from chimera_intel.core.negotiation_rl_agent import (
    QLearningAgent,
    QLearningLLMAgent,
    Transition,
)
from chimera_intel.core.llm_interface import MockLLMInterface
from chimera_intel.core.ethical_guardrails import EthicalFramework
from chimera_intel.core.dqn_model import DQN

class TestQLearningAgent(unittest.TestCase):
    """Tests for the simple QLearningAgent."""

    def setUp(self):
        self.agent = QLearningAgent(action_space_n=3, epsilon=0.1)
        self.state = {"feature1": 1, "feature2": 0}
        self.next_state = {"feature1": 2, "feature2": 1}

    def test_choose_action_epsilon(self):
        """Tests choosing an action randomly (epsilon path)."""
        with patch("random.uniform", return_value=0.05): # < epsilon
            action = self.agent.choose_action(self.state)
            self.assertIn(action, [0, 1, 2])

    def test_choose_action_q_table(self):
        """Tests choosing an action from the Q-table (greedy path)."""
        state_tuple = tuple(sorted(self.state.items()))
        self.agent.q_table[state_tuple] = [0.1, 0.5, 0.2] # Action 1 is max
        with patch("random.uniform", return_value=0.5): # > epsilon
            action = self.agent.choose_action(self.state)
            self.assertEqual(action, 1)

    def test_learn(self):
        """Tests the Q-table update logic."""
        state_tuple = tuple(sorted(self.state.items()))
        next_state_tuple = tuple(sorted(self.next_state.items()))
        
        self.agent.learn(self.state, 1, 0.5, self.next_state)
        
        # Check if tables were created
        self.assertIn(state_tuple, self.agent.q_table)
        self.assertIn(next_state_tuple, self.agent.q_table)
        
        # Check if value was updated (0 + 0.1 * (0.5 + 0.9 * 0))
        self.assertEqual(self.agent.q_table[state_tuple][1], 0.05)

    def test_save_and_load_model(self):
        """Tests saving and loading the Q-table."""
        state_tuple = tuple(sorted(self.state.items()))
        self.agent.q_table[state_tuple] = [1, 2, 3]
        
        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            # Test save
            with patch("json.dump") as mock_json_dump:
                self.agent.save_model("test.json")
                mock_json_dump.assert_called_once_with(self.agent.q_table, ANY)
            
            # Test load
            mock_file.return_value.read.return_value = '{"(1, 2)": [4, 5, 6]}'
            with patch("json.load", return_value={"(1, 2)": [4, 5, 6]}) as mock_json_load:
                self.agent.load_model("test.json")
                mock_json_load.assert_called_once()
                self.assertEqual(self.agent.q_table, {"(1, 2)": [4, 5, 6]})


class TestQLearningLLMAgent(unittest.IsolatedAsyncioTestCase):
    """Tests for the DQN-based QLearningLLMAgent."""

    def setUp(self):
        self.mock_llm = MockLLMInterface()
        self.mock_ethics = MagicMock(spec=EthicalFramework)
        
        # Mock DQN model
        self.patcher_dqn = patch("chimera_intel.core.negotiation_rl_agent.DQN")
        self.MockDQN = self.patcher_dqn.start()
        self.mock_policy_net = MagicMock(spec=DQN)
        self.mock_target_net = MagicMock(spec=DQN)
        
        # FIX: The .parameters() method must return a new iterator each time
        # it is called. Using side_effect achieves this.
        # This fixes the "list object is not an iterator" error (from next())
        # and the "optimizer receives an empty list" error (from consuming
        # a single iterator twice).
        def get_params_iterator():
            return iter([torch.nn.Parameter(torch.randn(1))])

        self.mock_policy_net.parameters.side_effect = get_params_iterator
        
        self.MockDQN.side_effect = [self.mock_policy_net, self.mock_target_net]
        
        self.agent = QLearningLLMAgent(
            llm=self.mock_llm,
            ethics=self.mock_ethics,
            db_params={},
            action_space_n=3,
        )
        self.agent.device = "cpu" # Force CPU for testing
        # self.mock_policy_net.device = "cpu" # Not needed, .to(device) will be mocked

    def tearDown(self):
        self.patcher_dqn.stop()

    def test_state_to_tensor(self):
        """Tests the conversion of state dict to tensor."""
        state = {
            "last_message_sentiment": "positive",
            "detected_tactics_in_last_message": ["tactic1", "tactic2"],
            "negotiation_turn_number": 5,
            "last_message_content": "I can offer $100.",
        }
        tensor = self.agent._state_to_tensor(state)
        expected = torch.tensor([[1, 2, 5, 1]], dtype=torch.float32) # sentiment, num_tactics, turn, offer
        self.assertTrue(torch.equal(tensor, expected))
        
        # Test default/missing values
        state_empty = {}
        tensor_empty = self.agent._state_to_tensor(state_empty)
        expected_empty = torch.tensor([[0, 0, 0, 0]], dtype=torch.float32)
        self.assertTrue(torch.equal(tensor_empty, expected_empty))

    def test_choose_action_epsilon(self):
        """Tests choosing an action randomly (epsilon path)."""
        self.agent.steps_done = 0
        with patch("random.random", return_value=0.0): # < eps_threshold
            action_tensor = self.agent.choose_action({})
            self.assertEqual(action_tensor.dim(), 2) # Shape [1, 1]
            self.assertIn(action_tensor.item(), [0, 1, 2])
            self.assertEqual(self.agent.steps_done, 1)

    def test_choose_action_policy(self):
        """Tests choosing an action from the policy network."""
        self.agent.steps_done = 10000 # Force greedy
        state = {"negotiation_turn_number": 2}
        
        # Mock policy net output
        # (batch_size, n_actions) -> (1, 3)
        mock_output = torch.tensor([[0.1, 0.5, 0.2]], dtype=torch.float32)
        self.mock_policy_net.return_value = mock_output
        
        action_tensor = self.agent.choose_action(state)
        self.assertEqual(action_tensor.item(), 1) # Index of max value
        self.mock_policy_net.assert_called_once() # Check that _state_to_tensor was called implicitly

    def test_construct_prompt(self):
        """Tests the prompt construction."""
        state = {"turn": 1}
        cultural_profile = {"style": "direct"}
        
        prompt = self.agent._construct_prompt(state, {})
        self.assertIn('"turn": 1', prompt)
        self.assertNotIn("cultural_profile", prompt)
        
        prompt_with_culture = self.agent._construct_prompt(state, cultural_profile)
        self.assertIn('"turn": 1', prompt_with_culture)
        self.assertIn("cultural profile", prompt_with_culture)
        self.assertIn('"style": "direct"', prompt_with_culture)

    # --- FIX: Added patch for 'get_cultural_profile' to prevent ConnectionError ---
    @patch("chimera_intel.core.negotiation_rl_agent.get_cultural_profile", return_value={})
    def test_generate_negotiation_message(self, mock_get_culture):
        """Tests message generation and ethical check."""
        self.mock_ethics.check_message.return_value = [] # No violations
        state = {"turn": 1}
        
        with patch.object(self.agent.llm, "generate_message", return_value={"message": "Test OK"}) as mock_gen:
            response = self.agent.generate_negotiation_message(state, [], "US", "persona")
            mock_gen.assert_called_once()
            self.mock_ethics.check_message.assert_called_once_with({"message": "Test OK"})
            self.assertEqual(response["message"], "Test OK")
            mock_get_culture.assert_called_once_with("US") # Verify mock was called

    def test_generate_negotiation_message_ethics_violation(self):
        """Tests message generation when an ethical violation is found."""
        self.mock_ethics.check_message.return_value = ["VIOLATION"] # Violation
        state = {"turn": 1}
        
        with patch.object(self.agent.llm, "generate_message", return_value={"message": "Bad message"}):
            response = self.agent.generate_negotiation_message(state, [])
            self.mock_ethics.check_message.assert_called_once_with({"message": "Bad message"})
            self.assertEqual(response["tactic"], "error")
            self.assertIn("ethical_violations", response)
            self.assertEqual(response["ethical_violations"], ["VIOLATION"])

    def test_optimize_model_not_enough_memory(self):
        """Tests that optimize_model returns early if memory is too small."""
        self.agent.memory = [1, 2, 3] # < batch_size (128)
        self.agent.optimize_model()
        # Optimizer won't be called, so policy_net won't be called for training
        # It was already called once in setUp
        self.assertEqual(self.mock_policy_net.call_count, 0) 
        
    @patch("random.sample")
    def test_optimize_model_step(self, mock_sample):
        """Tests a full optimization step."""
        # Populate memory
        state_tensor = self.agent._state_to_tensor({"turn": 1})
        next_state_tensor = self.agent._state_to_tensor({"turn": 2})
        # --- FIX: Ensure all tensors are created on the correct device ---
        action_tensor = torch.tensor([[1]], dtype=torch.long, device=self.agent.device)
        reward_tensor = torch.tensor([0.5], dtype=torch.float32, device=self.agent.device)
        # --- END FIX ---
        
        transitions = [
            Transition(state_tensor, action_tensor, next_state_tensor, reward_tensor)
        ] * self.agent.batch_size
        
        self.agent.memory = transitions
        mock_sample.return_value = transitions
        
        # --- FIX: Mock the *output* of the network calls ---
        # Mock the tensor returned by policy_net(...) and its .gather() method
        mock_policy_output = MagicMock(spec=torch.Tensor)
        mock_policy_output.gather.return_value = torch.rand(self.agent.batch_size, 1)
        self.mock_policy_net.return_value = mock_policy_output

        # Mock the tensor returned by target_net(...) and its .max() method
        # .max(1) returns a tuple (values, indices)
        mock_target_output = MagicMock(spec=torch.Tensor)
        
        # --- FIX for RuntimeError ---
        # The return value for .max(1)[0] must be shape [128], not [128, 1],
        # to match the shape of the masked next_state_values tensor it's being assigned to.
        mock_target_output.max.return_value = (torch.rand(self.agent.batch_size), None)
        
        self.mock_target_net.return_value = mock_target_output
        # --- END FIX ---

        # Mock optimizer
        self.agent.optimizer = MagicMock()
        self.agent.optimizer.zero_grad = MagicMock()
        self.agent.optimizer.step = MagicMock()
        
        # Mock loss
        mock_loss = MagicMock()
        mock_loss.backward = MagicMock()
        with patch("torch.nn.SmoothL1Loss", return_value=MagicMock(return_value=mock_loss)):
            self.agent.optimize_model()

            # Check that optimization happened
            self.agent.optimizer.zero_grad.assert_called_once()
            mock_loss.backward.assert_called_once()
            self.agent.optimizer.step.assert_called_once()
            
    @patch("torch.save")
    def test_save_model(self, mock_torch_save):
        """Tests saving the policy network state dict."""
        self.mock_policy_net.state_dict.return_value = {"key": "value"}
        self.agent.save_model("test.pth")
        mock_torch_save.assert_called_once_with({"key": "value"}, "test.pth")

    @patch("torch.load")
    def test_load_model(self, mock_torch_load):
        """Tests loading the state dict into both networks."""
        mock_torch_load.return_value = {"key": "value"}

        # --- FIX: Reset mocks to ignore any calls made during agent __init__ ---
        self.mock_policy_net.load_state_dict.reset_mock()
        self.mock_target_net.load_state_dict.reset_mock()
        # --- END FIX ---
        
        self.agent.load_model("test.pth")
        
        # --- FIX: This test should pass now that load_model is fixed ---
        mock_torch_load.assert_called_once_with("test.pth")
        self.mock_policy_net.load_state_dict.assert_called_once_with({"key": "value"})
        self.mock_target_net.load_state_dict.assert_called_once_with({"key": "value"})

    def test_mock_llm_interface(self):
        """
        Tests that the MockLLMInterface returns a response in the correct format.
        """
        response = self.mock_llm.generate_message("test prompt")
        self.assertIn("message", response)
        self.assertIsInstance(response["message"], str)

if __name__ == "__main__":
    unittest.main()