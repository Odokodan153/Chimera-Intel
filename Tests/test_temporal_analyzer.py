import unittest
from unittest.mock import patch, MagicMock
from httpx import Response
from typer.testing import CliRunner
from chimera_intel.core.temporal_analyzer import get_historical_snapshots
from chimera_intel.core.schemas import ShiftingIdentityResult

runner = CliRunner()


class TestTemporalAnalyzer(unittest.TestCase):
    """Test cases for the temporal_analyzer module."""

    @patch("chimera_intel.core.temporal_analyzer.sync_client.get")
    def test_get_historical_snapshots_success(self, mock_get):
        """Tests a successful snapshot retrieval."""
        # Arrange

        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        # Simulate the JSON list-of-lists response from the CDX API

        mock_response.json.return_value = [
            ["timestamp", "statuscode", "original"],
            ["20230101000000", "200", "http://example.com/"],
            ["20240101000000", "200", "https://example.com/"],
        ]
        mock_get.return_value = mock_response

        # Act

        result = get_historical_snapshots("example.com")

        # Assert

        self.assertIsInstance(result, ShiftingIdentityResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_snapshots_found, 2)
        self.assertEqual(result.snapshots[0].timestamp, "20230101000000")

    @patch("chimera_intel.core.temporal_analyzer.sync_client.get")
    def test_get_historical_snapshots_api_error(self, mock_get):
        """Tests error handling when the API call fails."""
        # Arrange

        mock_get.side_effect = Exception("API connection failed")

        # Act

        result = get_historical_snapshots("example.com")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("API error occurred", result.error)
        self.assertEqual(result.total_snapshots_found, 0)


if __name__ == "__main__":
    unittest.main()
