import pytest
from typer.testing import CliRunner
from unittest.mock import MagicMock, AsyncMock

# The application instance to be tested

from chimera_intel.core.historical_analyzer import historical_app

runner = CliRunner()


@pytest.fixture
def mock_get_historical_snapshots(mocker):
    """Mocks the get_historical_snapshots function."""
    mock_snapshot_result = MagicMock()
    mock_snapshot_result.error = None
    mock_snapshot_result.snapshots = [
        MagicMock(timestamp="20230101000000", url="http://example.com"),
        MagicMock(timestamp="20240101000000", url="http://example.com"),
    ]
    mocker.patch(
        "chimera_intel.core.historical_analyzer.get_historical_snapshots",
        return_value=mock_snapshot_result,
    )
    return mock_snapshot_result


@pytest.fixture
def mock_get_snapshot_content(mocker):
    """Mocks the get_snapshot_content async function."""

    async def async_magic():
        pass

    MagicMock.__await__ = lambda x: async_magic().__await__()

    mock = AsyncMock()
    mock.side_effect = [
        "Old content with removed text.",
        "New content with added text.",
    ]
    mocker.patch(
        "chimera_intel.core.historical_analyzer.get_snapshot_content", new=mock
    )
    return mock


@pytest.fixture
def mock_generate_swot_from_data(mocker):
    """Mocks the AI summary generation."""
    mock_summary_result = MagicMock()
    mock_summary_result.error = None
    mock_summary_result.analysis_text = "AI summary of changes."
    mocker.patch(
        "chimera_intel.core.historical_analyzer.generate_swot_from_data",
        return_value=mock_summary_result,
    )
    return mock_summary_result


def test_run_historical_analysis_success(
    mock_get_historical_snapshots,
    mock_get_snapshot_content,
    mock_generate_swot_from_data,
):
    """Tests the historical analysis command successfully."""
    result = runner.invoke(historical_app, ["run", "example.com"])

    assert result.exit_code == 0
    assert "Comparison between 20230101000000 and 20240101000000" in result.stdout
    assert "AI Summary of Changes:" in result.stdout
    assert "AI summary of changes." in result.stdout


def test_run_historical_analysis_no_snapshots(mocker):
    """Tests the command when no snapshots are found."""
    mock_snapshot_result = MagicMock()
    mock_snapshot_result.error = "No snapshots."
    mock_snapshot_result.snapshots = []
    mocker.patch(
        "chimera_intel.core.historical_analyzer.get_historical_snapshots",
        return_value=mock_snapshot_result,
    )

    result = runner.invoke(historical_app, ["run", "example.com"])

    assert result.exit_code == 1
    assert "Error:" in result.stdout
    assert "Could not retrieve historical snapshots" in result.stdout
