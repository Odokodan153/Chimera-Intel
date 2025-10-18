from typer.testing import CliRunner
from unittest.mock import patch
import typer  # Import typer

# Import the application instance and the SWOTAnalysisResult schema
from chimera_intel.core.red_team import red_team_app
from chimera_intel.core.schemas import SWOTAnalysisResult

app = typer.Typer()
app.add_typer(red_team_app)

runner = CliRunner()


def test_generate_scenario_success():
    """
    Tests the successful generation of a red team scenario.
    """
    with patch("chimera_intel.core.red_team.API_KEYS") as mock_api_keys, patch(
        "chimera_intel.core.red_team.get_aggregated_data_for_target"
    ) as mock_get_data, patch(
        "chimera_intel.core.red_team.generate_swot_from_data"
    ) as mock_generate_swot:

        # --- Setup Mocks ---

        mock_api_keys.google_api_key = "test_key"
        mock_get_data.return_value = {"vulnerabilities": ["CVE-2023-1234"]}
        mock_generate_swot.return_value = SWOTAnalysisResult(
            analysis_text="Scenario: Phishing campaign targeting employees.", error=None
        )

        # --- Run Command ---
        result = runner.invoke(app, ["red-team", "generate", "TestCorp"])

        # --- Assertions ---

        assert result.exit_code == 0
        assert "Generating potential attack vectors for TestCorp..." in result.stdout
        assert "Red Team Analysis for TestCorp" in result.stdout
        assert "Scenario: Phishing campaign targeting employees." in result.stdout


def test_generate_scenario_no_data():
    """
    Tests the command's behavior when no aggregated data is found for the target.
    """
    with patch("chimera_intel.core.red_team.API_KEYS") as mock_api_keys, patch(
        "chimera_intel.core.red_team.get_aggregated_data_for_target"
    ) as mock_get_data:
        # --- Setup Mocks ---

        mock_api_keys.google_api_key = "test_key"
        mock_get_data.return_value = None  # Simulate no data found

        # --- Run Command ---
        result = runner.invoke(app, ["red-team", "generate", "nonexistent-target"])

        # --- Assertions ---

        assert result.exit_code == 0
        assert "No data found for target 'nonexistent-target'" in result.stdout


def test_generate_scenario_no_api_key():
    """
    Tests that the command fails gracefully if the Google API key is not configured.
    """
    with patch("chimera_intel.core.red_team.API_KEYS") as mock_api_keys:
        # --- Setup Mock ---

        mock_api_keys.google_api_key = None  # Simulate missing API key

        # --- Run Command ---
        result = runner.invoke(app, ["red-team", "generate", "any-target"])

        # --- Assertions ---

        assert result.exit_code == 1
        assert "Error: Google API key not configured." in result.stdout