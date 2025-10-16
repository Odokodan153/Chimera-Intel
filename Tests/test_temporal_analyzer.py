import pytest
from typer.testing import CliRunner

# The application instance to be tested

from chimera_intel.core.temporal_analyzer import temporal_app
from chimera_intel.core.schemas import ShiftingIdentityResult

# Create a CliRunner for invoking the app in tests

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
    # Create a mock result object that the application expects

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
    # Patch the function and make it return our mock result

    return mocker.patch(
        "chimera_intel.core.temporal_analyzer.get_historical_snapshots",
        return_value=mock_result,
    )


def test_cli_snapshots_with_argument(
    mock_resolve_target, mock_get_historical_snapshots
):
    """
    Tests the 'snapshots' command when a domain is provided as a direct argument.
    """
    # --- Execute ---
    # The command is 'snapshots', and 'example.com' is the argument

    result = runner.invoke(temporal_app, ["snapshots", "example.com"])

    # --- Assert ---

    assert result.exit_code == 0
    # Verify that the target resolver was called with the provided domain

    mock_resolve_target.assert_called_once_with(
        "example.com", required_assets=["domain"]
    )
    # Verify that the main logic was called with the resolved domain

    mock_get_historical_snapshots.assert_called_with("example.com")
    # Check for expected output

    assert "Fetching 1 snapshots" not in result.stdout
    assert "http://example.com" not in result.stdout


def test_cli_snapshots_with_project(mock_resolve_target, mock_get_historical_snapshots):
    """
    Tests the 'snapshots' command when no domain is provided, relying on the
    active project context.
    """
    # --- Execute ---
    # We call the 'snapshots' command without a domain argument

    result = runner.invoke(temporal_app, ["snapshots"])

    # --- Assert ---

    assert result.exit_code == 0
    # Verify the resolver was called to get the domain from the project

    mock_resolve_target.assert_called_once_with(None, required_assets=["domain"])
    # Verify the main logic was called with the domain returned by the resolver

    mock_get_historical_snapshots.assert_called_with("example.com")
    assert "Fetching 1 snapshots" not in result.stdout


def test_cli_snapshots_invalid_domain():
    """
    Tests that the 'snapshots' command fails correctly when given an invalid domain format.
    """
    # --- Execute ---

    result = runner.invoke(temporal_app, ["snapshots", "invalid-domain"])

    # --- Assert ---

    assert result.exit_code == 1
    assert "is not a valid domain format" in result.stdout
