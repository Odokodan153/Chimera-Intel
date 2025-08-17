import unittest
from unittest.mock import patch, MagicMock
from chimera_intel.core.strategist import generate_strategic_profile

class TestStrategist(unittest.TestCase):
    """Test cases for the strategist module."""

    @patch("chimera_intel.core.strategist.genai")
    def test_generate_strategic_profile_success(self, mock_genai):
        """Tests a successful strategic profile generation."""
        mock_model = mock_genai.GenerativeModel.return_value
        mock_model.generate_content.return_value.text = "This is a strategic profile."

        test_data = {"target": "example.com", "modules": {}}
        result = generate_strategic_profile(test_data, "fake_api_key")

        self.assertEqual(result.profile_text, "This is a strategic profile.")
        self.assertIsNone(result.error)
        mock_genai.configure.assert_called_once_with(api_key="fake_api_key")

    def test_generate_strategic_profile_no_key(self):
        """Tests profile generation when the API key is missing."""
        result = generate_strategic_profile({}, "")
        self.assertIsNotNone(result.error)
        self.assertIn("not found", result.error)

    @patch("chimera_intel.core.strategist.genai")
    def test_generate_strategic_profile_api_error(self, mock_genai):
        """Tests profile generation when the API call fails."""
        mock_model = mock_genai.GenerativeModel.return_value
        mock_model.generate_content.side_effect = Exception("API Error")

        result = generate_strategic_profile({}, "fake_api_key")
        self.assertIsNotNone(result.error)
        self.assertIn("API Error", result.error)

if __name__ == '__main__':
    unittest.main()