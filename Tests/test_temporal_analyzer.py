import pytest
from typer.testing import CliRunner

# ---: Import the MAIN app and the app to be tested ---

from chimera_intel.cli import app as main_app
from chimera_intel.core.temporal_analyzer import temporal_app
from chimera_intel.core.schemas import ShiftingIdentityResult

# ---: Manually register the app as a plugin ---

main_app.add_typer(temporal_app, name="temporal")

runner = CliRunner()


@pytest.fixture
def mock_resolve_target(mocker):
    """A pytest fixture to mock the project and target resolution logic."""
    return mocker.patch(
        "chimera_intel.core.temporal_analyzer.resolve_target",
        return_value="example.com",
    )


@pytest.fixture
def mock_get_historical_snapshots(mocker):
    """
    A pytest fixture that mocks the core data gathering function,
    preventing actual network calls.
    """
    mock_result = ShiftingIdentityResult(
        domain="example.com",
        total_snapshots_found=1,
        snapshots=[
            {
                "url": "http://example.com",
                "timestamp": "20230101000000",
                "status_code": 200,
            }
        ],
    )
    return mocker.patch(
        "chimera_intel.core.temporal_analyzer.get_historical_snapshots",
        return_value=mock_result,
    )


@pytest.fixture(autouse=True)
def mock_output_functions(mocker):
    """Mocks functions that print, save files, or write to the DB."""
    mocker.patch("chimera_intel.core.temporal_analyzer.save_or_print_results")
    mocker.patch("chimera_intel.core.temporal_analyzer.save_scan_to_db")


def test_cli_snapshots_with_argument(
    mock_resolve_target, mock_get_historical_snapshots
):
    """
    Tests the 'snapshots' command when a domain is provided as a direct argument.
    """
    # --- Execute ---
    # ---: Invoke the main_app with the full command ---

    result = runner.invoke(main_app, ["temporal", "snapshots", "example.com"])

    # --- Assert ---

    assert result.exit_code == 0
    mock_resolve_target.assert_called_once_with(
        "example.com", required_assets=["domain"]
    )
    mock_get_historical_snapshots.assert_called_with("example.com")
    # Original assertions of absence are fine, as we mock the print function

    assert "Fetching 1 snapshots" not in result.stdout
    assert "http://example.com" not in result.stdout


def test_cli_snapshots_with_project(mock_resolve_target, mock_get_historical_snapshots):
    """
    Tests the 'snapshots' command when no domain is provided, relying on the
    active project context.
    """
    # --- Execute ---
    # ---: Invoke the main_app with the full command ---

    result = runner.invoke(main_app, ["temporal", "snapshots"])

    # --- Assert ---

    assert result.exit_code == 0
    # --- : The mock assertion is now correct ---

    mock_resolve_target.assert_called_once_with(None, required_assets=["domain"])
    mock_get_historical_snapshots.assert_called_with("example.com")
    assert "Fetching 1 snapshots" not in result.stdout


def test_cli_snapshots_invalid_domain(mocker, mock_output_functions):
    """
    Tests that the 'snapshots' command fails correctly when given an invalid domain format.
    """
    # --- Setup ---
    # Mock resolve_target to return the invalid domain for validation

    mock_resolve = mocker.patch(
        "chimera_intel.core.temporal_analyzer.resolve_target",
        return_value="invalid-domain",
    )

    # --- Execute ---
    # ---: Invoke the main_app with the full command ---

    result = runner.invoke(main_app, ["temporal", "snapshots", "invalid-domain"])

    # --- Assert ---
    # ---: The exit code is 1 (logic) not 2 (parsing) ---

    assert result.exit_code == 1
    assert "is not a valid domain format" in result.stdout
    # Verify the resolver was called correctly

    mock_resolve.assert_called_once_with("invalid-domain", required_assets=["domain"])
