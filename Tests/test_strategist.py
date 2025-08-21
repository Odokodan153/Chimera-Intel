import unittest
from unittest.mock import patch
from typer.testing import CliRunner
from chimera_intel.cli import app
from chimera_intel.core.strategist import (
    generate_strategic_profile,
)
from chimera_intel.core.schemas import StrategicProfileResult

# FIX: Do not mix stderr to allow for separate checking of stderr
# This is the corrected initialization.


runner = CliRunner(mix_stderr=False)


class TestStrategist(unittest.TestCase):
    """
    Extended test cases for the strategist module, covering core logic and CLI commands.
    """

    # FIX: Correct the patch to target the class where it's defined (at the source)
    # This is more robust than targeting where it's imported.

    @patch("chimera_intel.core.strategist.genai.GenerativeModel")
    @patch("chimera_intel.core.strategist.API_KEYS")
    def test_generate_strategic_profile_success(self, mock_api_keys, mock_model):
        """
        Tests a successful strategic profile generation, ensuring the API is called correctly.
        """
        # --- Arrange ---
        # Mock the API key and the generative model's response

        mock_api_keys.google_api_key = "fake_google_key"
        mock_instance = mock_model.return_value
        mock_instance.generate_content.return_value.text = "## Strategic Analysis"
        test_data = {"domain": "example.com", "tech": ["React"]}

        # --- Act ---
        # Call the function with test data

        result = generate_strategic_profile(test_data, "fake_google_key")

        # --- Assert ---
        # Verify the result object is correct

        self.assertIsInstance(result, StrategicProfileResult)
        self.assertEqual(result.profile_text, "## Strategic Analysis")
        self.assertIsNone(result.error)
        # Verify that the model was called exactly once

        mock_model.return_value.generate_content.assert_called_once()

    def test_generate_strategic_profile_no_api_key(self):
        """
        Tests that the function returns an error immediately if no API key is provided.
        """
        # --- Act ---

        result = generate_strategic_profile({}, "")

        # --- Assert ---

        self.assertIsInstance(result, StrategicProfileResult)
        self.assertIn("GOOGLE_API_KEY not found", result.error)

    # FIX: Correct the patch to target the class where it's defined

    @patch("chimera_intel.core.strategist.genai.GenerativeModel")
    @patch("chimera_intel.core.strategist.API_KEYS")
    def test_generate_strategic_profile_api_exception(self, mock_api_keys, mock_model):
        """
        Tests error handling when the Google AI API raises an exception.
        """
        # --- Arrange ---

        mock_api_keys.google_api_key = "fake_google_key"
        # Configure the mock to raise a generic exception

        mock_model.return_value.generate_content.side_effect = Exception(
            "API connection timed out"
        )

        # --- Act ---

        result = generate_strategic_profile({}, "fake_google_key")

        # --- Assert ---

        self.assertIsInstance(result, StrategicProfileResult)
        self.assertIn("API connection timed out", result.error)
        self.assertIsNone(result.profile_text)

    @patch("chimera_intel.core.strategist.get_aggregated_data_for_target")
    @patch("chimera_intel.core.strategist.generate_strategic_profile")
    @patch("chimera_intel.core.strategist.API_KEYS")
    def test_cli_strategy_command_success(
        self, mock_api_keys, mock_generate, mock_get_data
    ):
        """
        Tests a successful run of the `analysis strategy run` CLI command.
        """
        # --- Arrange ---

        mock_api_keys.google_api_key = "fake_google_key"
        mock_get_data.return_value = {"target": "example.com", "modules": {}}
        mock_generate.return_value = StrategicProfileResult(profile_text="**Success**")

        # --- Act ---

        result = runner.invoke(app, ["analysis", "strategy", "run", "example.com"])

        # --- Assert ---

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Success", result.stdout)
        mock_get_data.assert_called_once_with("example.com")
        mock_generate.assert_called_once()

    @patch("chimera_intel.core.strategist.get_aggregated_data_for_target")
    @patch("chimera_intel.core.strategist.API_KEYS")
    def test_cli_strategy_no_historical_data(self, mock_api_keys, mock_get_data):
        """
        Tests the CLI command's behavior when no historical data is found for the target.
        """
        # --- Arrange ---

        mock_api_keys.google_api_key = "fake_google_key"
        mock_get_data.return_value = None  # Simulate no data in the database

        # --- Act ---

        result = runner.invoke(app, ["analysis", "strategy", "run", "nonexistent.com"])

        # --- Assert ---
        # The command should exit with a non-zero status code to indicate failure

        self.assertEqual(result.exit_code, 1)
        # It should not attempt to generate a profile

        self.assertNotIn("Automated Strategic Profile", result.stdout)

    @patch("chimera_intel.core.strategist.get_aggregated_data_for_target")
    @patch("chimera_intel.core.strategist.API_KEYS")
    def test_cli_strategy_missing_api_key(self, mock_api_keys, mock_get_data):
        """
        Tests the CLI command's failure when the GOOGLE_API_KEY is not configured.
        """
        # --- Arrange ---

        mock_api_keys.google_api_key = None  # Simulate a missing key
        mock_get_data.return_value = {"target": "example.com", "modules": {}}

        # --- Act ---

        result = runner.invoke(app, ["analysis", "strategy", "run", "example.com"])

        # --- Assert ---

        self.assertEqual(result.exit_code, 1)
        # With mix_stderr=False, we can now check the stderr stream

        self.assertIn("Google API key not found", result.stderr)

    @patch("chimera_intel.core.strategist.get_aggregated_data_for_target")
    @patch("chimera_intel.core.strategist.generate_strategic_profile")
    @patch("chimera_intel.core.strategist.API_KEYS")
    def test_cli_strategy_handles_generation_error(
        self, mock_api_keys, mock_generate, mock_get_data
    ):
        """
        Tests that the CLI command correctly handles an error from the AI generation function.
        """
        # --- Arrange ---

        mock_api_keys.google_api_key = "fake_google_key"
        mock_get_data.return_value = {"target": "example.com", "modules": {}}
        # Simulate the AI function returning an error

        mock_generate.return_value = StrategicProfileResult(error="AI service is down")

        # --- Act ---

        result = runner.invoke(app, ["analysis", "strategy", "run", "example.com"])

        # --- Assert ---
        # The command should exit cleanly, but log an error to stderr

        self.assertEqual(result.exit_code, 0)
        # With mix_stderr=False, we can check the error message in stderr

        self.assertIn("Failed to generate strategic profile", result.stderr)
        self.assertNotIn(
            "AI service is down", result.stdout
        )  # Ensure error isn't in stdout
        self.assertIn("No analysis generated", result.stdout)


if __name__ == "__main__":
    unittest.main()
