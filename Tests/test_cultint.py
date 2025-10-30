from typer.testing import CliRunner
from unittest.mock import patch
import typer

# The application instance to be tested
from chimera_intel.core.cultint import cultint_app
from chimera_intel.core.schemas import SWOTAnalysisResult

runner = CliRunner()

# FIX: Wrap the sub-app in a parent Typer for correct test invocation
app = typer.Typer()
app.add_typer(cultint_app, name="cultint")


@patch("chimera_intel.core.cultint.get_aggregated_data_for_target")
@patch("chimera_intel.core.cultint.generate_swot_from_data")
@patch("chimera_intel.core.cultint.API_KEYS")
def test_analyze_target_success(mock_api_keys, mock_generate_swot, mock_get_data):
    """
    Tests the successful run of a CULTINT analysis.
    """
    # --- Setup Mocks ---
    # 1. Mock the API key to ensure the check passes.
    mock_api_keys.google_api_key = "test_key"

    # 2. Mock the aggregated data returned from the database.
    mock_get_data.return_value = {
        "modules": {
            "social_analyzer": {"sentiment": "positive"},
            "business_intel": {"news": ["Some news article"]},
            "corporate_hr_intel": {"reviews": ["A review"]},
        }
    }

    # 3. Mock the AI analysis result.
    mock_ai_result = SWOTAnalysisResult(
        analysis_text="Analysis shows a hierarchical culture focused on tradition.",
        error=None,
    )
    mock_generate_swot.return_value = mock_ai_result

    # --- Run Command ---
    # FIX: Invoke the parent 'app' with the full command 'cultint analyze'
    result = runner.invoke(app, ["cultint", "analyze", "TestCorp"])

    # --- Assertions ---
    assert result.exit_code == 0, result.output
    assert "Analyzing cultural narrative for TestCorp..." in result.stdout
    assert "Cultural Narrative Analysis for TestCorp" in result.stdout
    assert "Analysis shows a hierarchical culture" in result.stdout

    # Verify the AI prompt was generated correctly
    mock_generate_swot.assert_called_once()
    prompt_arg = mock_generate_swot.call_args[0][0]
    assert (
        "As a cultural intelligence analyst, analyze the following data collected on TestCorp"
        in prompt_arg
    )
    assert "'social_media': {'sentiment': 'positive'}" in prompt_arg


@patch("chimera_intel.core.cultint.console.print")
@patch("chimera_intel.core.cultint.get_aggregated_data_for_target")
@patch("chimera_intel.core.cultint.API_KEYS")
def test_analyze_target_no_data(mock_api_keys, mock_get_data, mock_console):
    """
    Tests the command's behavior when no aggregated data is found for the target.
    """
    # --- Setup Mocks ---
    mock_api_keys.google_api_key = "test_key"
    mock_get_data.return_value = None  # Simulate no data found

    # --- Run Command ---
    # FIX: Invoke the parent 'app' with the full command 'cultint analyze'
    result = runner.invoke(app, ["cultint", "analyze", "nonexistent-target"])

    # --- Assertions ---
    # Check that the intended exit code was 0
    exit_code = result.exit_code
    if isinstance(result.exception, typer.Exit):
        exit_code = result.exception.exit_code

    assert exit_code == 0
    # Check that the correct warning was printed to the console
    mock_console.assert_any_call(
        "[yellow]Warning:[/] No relevant data sources (social media, news, HR intel) found for 'nonexistent-target' to analyze cultural narrative."
    )


@patch("chimera_intel.core.cultint.console.print")
@patch("chimera_intel.core.cultint.API_KEYS")
def test_analyze_target_no_api_key(mock_api_keys, mock_console):
    """
    Tests that the command fails gracefully if the Google API key is not configured.
    """
    # --- Setup Mock ---
    mock_api_keys.google_api_key = None  # Simulate missing API key

    # --- Run Command ---
    # FIX: Invoke the parent 'app' with the full command 'cultint analyze'
    result = runner.invoke(app, ["cultint", "analyze", "any-target"])

    # --- Assertions ---
    # Check that the intended exit code was 1
    exit_code = result.exit_code
    if isinstance(result.exception, typer.Exit):
        exit_code = result.exception.exit_code

    assert exit_code == 1
    # Check that the correct error was printed to the console
    mock_console.assert_any_call(
        "[bold red]Error:[/bold red] Google API key not configured."
    )
