import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import Response

# The application instance to be tested

from chimera_intel.core.web_analyzer import web_app
from chimera_intel.core.schemas import WebAnalysisResult

# Create a CliRunner for invoking the app in tests

runner = CliRunner()


@pytest.fixture(autouse=True)
def clear_cache():
    """
    A pytest fixture that automatically clears the application's in-memory
    cache before each test runs, ensuring test isolation.
    """
    from chimera_intel.core.web_analyzer import API_CACHE

    API_CACHE.clear()


@pytest.fixture
def mock_api_keys(mocker):
    """Mocks all necessary API keys for the web analyzer module."""
    return mocker.patch(
        "chimera_intel.core.web_analyzer.API_KEYS",
        builtwith_api_key="fake_builtwith_key",
        wappalyzer_api_key="fake_wappalyzer_key",
        similarweb_api_key="fake_similarweb_key",
    )


@pytest.mark.asyncio
@patch("chimera_intel.core.web_analyzer.take_screenshot", new_callable=AsyncMock)
@patch("chimera_intel.core.web_analyzer.get_traffic_similarweb", new_callable=AsyncMock)
@patch(
    "chimera_intel.core.web_analyzer.get_tech_stack_wappalyzer", new_callable=AsyncMock
)
@patch(
    "chimera_intel.core.web_analyzer.get_tech_stack_builtwith", new_callable=AsyncMock
)
async def test_gather_web_analysis_data_success(
    mock_builtwith, mock_wappalyzer, mock_similarweb, mock_screenshot, mock_api_keys
):
    """
    Tests the successful orchestration of all web analysis data gathering tasks.
    """
    # --- Arrange ---
    # Set up return values for all the mocked async functions

    mock_builtwith.return_value = ["Nginx", "jQuery"]
    mock_wappalyzer.return_value = ["Nginx", "React"]
    mock_similarweb.return_value = {"visits": [1000, 2000]}
    mock_screenshot.return_value = "/screenshots/example.com.png"

    # --- Act ---
    # Import the function locally to use the patched dependencies

    from chimera_intel.core.web_analyzer import gather_web_analysis_data

    result = await gather_web_analysis_data("example.com")

    # --- Assert ---

    assert isinstance(result, WebAnalysisResult)
    assert result.domain == "example.com"
    # Nginx (2 sources), jQuery (1), React (1) should result in 3 unique techs

    assert result.web_analysis.tech_stack.total_unique == 3
    assert result.web_analysis.screenshot_path == "/screenshots/example.com.png"
    assert "visits" in result.web_analysis.traffic_info


@patch("chimera_intel.core.web_analyzer.resolve_target")
@patch(
    "chimera_intel.core.web_analyzer.gather_web_analysis_data", new_callable=AsyncMock
)
def test_cli_run_success(mock_gather_data, mock_resolve_target):
    """
    Tests a successful run of the 'web run' CLI command.
    """
    # --- Arrange ---
    # Mock the function that resolves the target domain

    mock_resolve_target.return_value = "example.com"

    # Mock the main data gathering function to return a result object

    mock_result_instance = MagicMock()
    mock_result_instance.model_dump.return_value = {
        "domain": "example.com",
        "web_analysis": {
            "tech_stack": {"total_unique": 1, "results": [{"technology": "React"}]}
        },
    }
    mock_gather_data.return_value = mock_result_instance

    # --- Act ---
    # Invoke the CLI command correctly: `run` is the command, `example.com` is the argument

    result = runner.invoke(web_app, ["run", "example.com"])

    # --- Assert ---

    assert result.exit_code == 0
    # Verify the core logic was called with the correct domain

    mock_gather_data.assert_awaited_with("example.com")
    # Check for expected output in the console

    assert '"domain": "example.com"' in result.stdout
    assert '"technology": "React"' in result.stdout


def test_cli_run_invalid_domain():
    """
    Tests that the 'web run' CLI command fails correctly with an invalid domain format.
    """
    # --- Act ---

    result = runner.invoke(web_app, ["run", "invalid-domain"])

    # --- Assert ---

    assert result.exit_code == 1
    assert "is not a valid domain format" in result.stdout
