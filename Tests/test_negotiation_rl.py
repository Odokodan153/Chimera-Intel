import unittest
from .negotiation import NegotiationEngine
from .llm_interface import MockLLMInterface

class TestNegotiationRL(unittest.TestCase):

    def setUp(self):
        self.engine = NegotiationEngine()
        self.mock_llm = MockLLMInterface()

    def test_mock_llm_interface(self):
        """
        Tests that the MockLLMInterface returns a response in the correct format.
        """
        response = self.mock_llm.generate_message("test prompt")
        self.assertIn("message", response)
        self.assertIsInstance(response["message"], str)

    def test_get_reward(self):
        """
        Tests the get_reward function to ensure it calculates rewards as expected.
        """
        positive_state = {"last_message_sentiment": "positive"}
        negative_state = {"last_message_sentiment": "negative"}
        neutral_state = {"last_message_sentiment": "neutral"}

        self.assertEqual(self.engine.get_reward(positive_state), 0.1)
        self.assertEqual(self.engine.get_reward(negative_state), -0.1)
        self.assertEqual(self.engine.get_reward(neutral_state), 0)

    def test_mock_llm_interface(self):
        """
        Tests that the MockLLMInterface returns a response in the correct format.
        """
        response = self.mock_llm.generate_message("test prompt")
        self.assertIn("message", response)
        self.assertIsInstance(response["message"], str)

    def test_get_reward(self):
        """
        Tests the get_reward function to ensure it calculates rewards as expected.
        """
        positive_state = {"last_message_sentiment": "positive"}
        negative_state = {"last_message_sentiment": "negative"}
        neutral_state = {"last_message_sentiment": "neutral"}
        offer_state = {"last_message_content": "I can offer you a 15% discount."}
        accept_state = {"last_message_content": "I accept your offer."}
        reject_state = {"last_message_content": "I must reject that offer."}

        self.assertEqual(self.engine.get_reward(positive_state), 0.2)
        self.assertEqual(self.engine.get_reward(negative_state), -0.2)
        self.assertEqual(self.engine.get_reward(neutral_state), 0)
        self.assertGreater(self.engine.get_reward(offer_state), 0)
        self.assertGreater(self.engine.get_reward(accept_state), 0)
        self.assertLess(self.engine.get_reward(reject_state), 0)

if __name__ == '__main__':
    unittest.main()