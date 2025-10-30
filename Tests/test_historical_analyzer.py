import unittest
from unittest.mock import patch, AsyncMock
from typer.testing import CliRunner

from chimera_intel.core.historical_analyzer import (
    analyze_historical_changes,
    historical_app,
)
from chimera_intel.core.schemas import (
    HistoricalAnalysisResult,
    ShiftingIdentityResult,
    TemporalSnapshot,
    SWOTAnalysisResult,
)

runner = CliRunner()


class TestHistoricalAnalyzer(unittest.IsolatedAsyncioTestCase):
    """Test cases for the Historical Website Analysis module."""

    # --- Function Tests ---

    @patch("chimera_intel.core.historical_analyzer.get_historical_snapshots")
    @patch(
        "chimera_intel.core.historical_analyzer.get_snapshot_content",
        new_callable=AsyncMock,
    )
    @patch("chimera_intel.core.historical_analyzer.generate_swot_from_data")
    @patch("chimera_intel.core.historical_analyzer.API_KEYS")
    async def test_analyze_historical_changes_success(
        self,
        mock_api_keys,
        mock_gen_swot,
        mock_get_content,
        mock_get_snapshots,
    ):
        """Tests a successful historical analysis with AI summary."""
        # Arrange

        mock_api_keys.google_api_key = "fake_key"
        mock_get_snapshots.return_value = ShiftingIdentityResult(
            domain="example.com",
            total_snapshots_found=2,
            snapshots=[
                TemporalSnapshot(
                    url="http://example.com",
                    timestamp="20220101000000",
                    status_code=200,
                ),
                TemporalSnapshot(
                    url="http://example.com",
                    timestamp="20230101000000",
                    status_code=200,
                ),
            ],
        )
        mock_get_content.side_effect = ["Old content", "New content"]
        mock_gen_swot.return_value = SWOTAnalysisResult(
            analysis_text="AI summary of changes."
        )

        # Act

        result = await analyze_historical_changes("example.com")

        # Assert

        self.assertIsInstance(result, HistoricalAnalysisResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.from_timestamp, "20220101000000")
        self.assertEqual(result.to_timestamp, "20230101000000")
        self.assertIn("-Old content", result.diff)
        self.assertIn("+New content", result.diff)
        self.assertEqual(result.ai_summary, "AI summary of changes.")
        mock_gen_swot.assert_called_once()

    @patch("chimera_intel.core.historical_analyzer.get_historical_snapshots")
    async def test_analyze_historical_changes_no_snapshots(self, mock_get_snapshots):
        """Tests the case where no historical snapshots are found."""
        # Arrange

        mock_get_snapshots.return_value = ShiftingIdentityResult(
            domain="example.com", total_snapshots_found=0, snapshots=[]
        )

        # Act

        result = await analyze_historical_changes("example.com")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("Could not retrieve historical snapshots", result.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.historical_analyzer.asyncio.run")
    @patch("chimera_intel.core.historical_analyzer.analyze_historical_changes")
    def test_cli_run_historical_analysis_success(self, mock_analyze, mock_asyncio_run):
        """Tests a successful run of the 'historical-analyzer run' command."""
        # Arrange
        # The mock_analyze function is what's being run by asyncio.run
        # We need to mock its return value, not the return value of asyncio.run

        mock_result = HistoricalAnalysisResult(
            domain="example.com",
            from_timestamp="2022",
            to_timestamp="2023",
            ai_summary="CLI AI Summary",
        )
        # Configure the mock analyze_historical_changes to be the one asyncio.run executes

        mock_asyncio_run.return_value = mock_result

        # We also need to mock the function call *inside* the asyncio.run target
        # A bit complex, but let's assume the CLI function calls analyze_historical_changes
        # and asyncio.run wraps that CLI function.
        # The mock setup from the original file is likely correct, let's stick to that.
        # The key is the runner.invoke call.

        # Act
        # FIX: Removed "run" from the list

        result = runner.invoke(historical_app, ["example.com"])

        # Assert

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIsNone(result.exception)
        self.assertIn("Comparison between 2022 and 2023", result.stdout)
        self.assertIn("CLI AI Summary", result.stdout)

        # Check that asyncio.run was called, and it subsequently called analyze

        mock_asyncio_run.assert_called_once()

        pass  # The original test code for setup is fine, just the invoke was wrong.

    @patch("chimera_intel.core.historical_analyzer.asyncio.run")
    def test_cli_run_historical_analysis_error(self, mock_asyncio_run):
        """Tests the CLI command when the underlying analysis function returns an error."""
        # Arrange

        mock_result = HistoricalAnalysisResult(
            domain="example.com", error="Could not find snapshots."
        )
        mock_asyncio_run.return_value = mock_result

        # Act
        # FIX: Removed "run" from the list

        result = runner.invoke(historical_app, ["example.com"])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIsInstance(result.exception, SystemExit)
        self.assertIn("Could not find snapshots", result.stdout)
        mock_asyncio_run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
