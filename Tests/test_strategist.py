import unittest
from unittest.mock import patch
from typer.testing import CliRunner

from chimera_intel.cli import app
from chimera_intel.core.strategist import generate_strategic_profile

runner = CliRunner()


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

    # CLI Tests

    @patch("chimera_intel.core.strategist.get_aggregated_data_for_target")
    @patch("chimera_intel.core.strategist.generate_strategic_profile")
    @patch("chimera_intel.core.strategist.API_KEYS.google_api_key", "fake_key")
    def test_cli_strategy_run_success(self, mock_generate, mock_get_data):
        """Tests a successful 'strategy run' CLI command."""
        mock_get_data.return_value = {"target": "example.com"}
        mock_generate.return_value.profile_text = "Strategic text"
        mock_generate.return_value.error = None

        result = runner.invoke(app, ["analysis", "strategy", "run", "example.com"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Strategic text", result.stdout)

    @patch("chimera_intel.core.strategist.get_aggregated_data_for_target")
    def test_cli_strategy_run_no_data(self, mock_get_data):
        """Tests the 'strategy run' command when no historical data is found."""
        mock_get_data.return_value = None

        result = runner.invoke(app, ["analysis", "strategy", "run", "example.com"])

        self.assertEqual(result.exit_code, 1)

    @patch("chimera_intel.core.strategist.get_aggregated_data_for_target")
    @patch("chimera_intel.core.strategist.API_KEYS.google_api_key", None)
    def test_cli_strategy_run_no_api_key(self, mock_get_data):
        """Tests the 'strategy run' command when the API key is missing."""
        mock_get_data.return_value = {"target": "example.com"}

        result = runner.invoke(app, ["analysis", "strategy", "run", "example.com"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Google API key not found", result.stdout)


if __name__ == "__main__":
    unittest.main()
