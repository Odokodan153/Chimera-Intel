import unittest
import json
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from httpx import Response, RequestError

from chimera_intel.core.temporal_analyzer import (
    get_historical_snapshots,
    temporal_app,
)
from chimera_intel.core.schemas import (
    ShiftingIdentityResult,
    TemporalSnapshot,
    ProjectConfig,
)

runner = CliRunner()


class TestTemporalAnalyzer(unittest.TestCase):
    """Test cases for the Temporal Analysis module."""

    # --- Function Tests ---

    @patch("chimera_intel.core.temporal_analyzer.sync_client.get")
    def test_get_historical_snapshots_success(self, mock_get):
        """Tests a successful fetch of historical snapshots."""
        # Arrange

        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        # Simulate the CDX API JSON format: [header, [data], [data], ...]

        mock_response.json.return_value = [
            ["timestamp", "statuscode", "original"],
            ["20230101000000", "200", "http://example.com/"],
            ["20220101000000", "200", "http://example.com/"],
        ]
        mock_get.return_value = mock_response

        # Act

        result = get_historical_snapshots("example.com")

        # Assert

        self.assertIsInstance(result, ShiftingIdentityResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_snapshots_found, 2)
        self.assertEqual(len(result.snapshots), 2)
        self.assertEqual(result.snapshots[0].timestamp, "20230101000000")

    @patch("chimera_intel.core.temporal_analyzer.sync_client.get")
    def test_get_historical_snapshots_api_error(self, mock_get):
        """Tests the function's error handling when the API fails."""
        # Arrange

        mock_get.side_effect = RequestError("Service Unavailable")

        # Act

        result = get_historical_snapshots("example.com")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("An API error occurred", result.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.temporal_analyzer.get_historical_snapshots")
    def test_cli_snapshots_with_argument(self, mock_get_snapshots):
        """Tests the 'temporal snapshots' command with a direct argument."""
        # Arrange

        mock_get_snapshots.return_value = ShiftingIdentityResult(
            domain="example.com", total_snapshots_found=5
        )

        # Act

        result = runner.invoke(temporal_app, ["snapshots", "example.com"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_get_snapshots.assert_called_with("example.com")
        output = json.loads(result.stdout)
        self.assertEqual(output["domain"], "example.com")
        self.assertEqual(output["total_snapshots_found"], 5)

    @patch("chimera_intel.core.temporal_analyzer.resolve_target")
    @patch("chimera_intel.core.temporal_analyzer.get_historical_snapshots")
    def test_cli_snapshots_with_project(self, mock_get_snapshots, mock_resolve_target):
        """Tests the CLI command using an active project's domain."""
        # Arrange

        mock_resolve_target.return_value = "project.com"
        mock_get_snapshots.return_value = ShiftingIdentityResult(
            domain="project.com", total_snapshots_found=10
        )

        # Act

        result = runner.invoke(temporal_app, ["snapshots"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_resolve_target.assert_called_with(None, required_assets=["domain"])
        mock_get_snapshots.assert_called_with("project.com")
        self.assertIn('"total_snapshots_found": 10', result.stdout)

    def test_cli_snapshots_invalid_domain(self):
        """Tests the CLI command with an invalid domain."""
        result = runner.invoke(temporal_app, ["snapshots", "invalid-domain"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("is not a valid domain format", result.stdout)


if __name__ == "__main__":
    unittest.main()
