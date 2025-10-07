import unittest
import json
from unittest.mock import patch
from typer.testing import CliRunner
import typer

from chimera_intel.core.finint import track_insider_trading, finint_app
from chimera_intel.core.schemas import (
    InsiderTradingResult
)

runner = CliRunner()


class TestFinint(unittest.TestCase):
    """Test cases for the Financial Intelligence (FININT) module."""

    @patch("chimera_intel.core.finint.InsiderTradingApi")
    @patch("chimera_intel.core.finint.API_KEYS")
    def test_track_insider_trading_success(self, mock_api_keys, mock_insider_api):
        """Tests a successful insider trading lookup."""
        # Arrange

        mock_api_keys.sec_api_io_key = "fake_sec_key"
        mock_api_instance = mock_insider_api.return_value
        mock_api_instance.get_insider_transactions.return_value = {
            "total": 1,
            "transactions": [
                {
                    "companyName": "Apple Inc.",
                    "insiderName": "John Doe",
                    "transactionType": "P-Purchase",
                    "transactionDate": "2023-10-26",
                    "shares": 100,
                    "value": 10000,
                }
            ],
        }

        # Act

        result = track_insider_trading("AAPL")

        # Assert

        self.assertIsInstance(result, InsiderTradingResult)
        self.assertEqual(result.total_transactions, 1)
        self.assertEqual(len(result.transactions), 1)
        self.assertEqual(result.transactions[0].insiderName, "John Doe")
        self.assertIsNone(result.error)

    def test_track_insider_trading_no_api_key(self):
        """Tests insider trading tracking when the SEC API key is missing."""
        with patch("chimera_intel.core.finint.API_KEYS.sec_api_io_key", None):
            result = track_insider_trading("AAPL")
            self.assertIsNotNone(result.error)
            self.assertIn("SEC API (sec-api.io) key not found", result.error)

    @patch("chimera_intel.core.finint.InsiderTradingApi")
    @patch("chimera_intel.core.finint.API_KEYS")
    def test_track_insider_trading_api_error(self, mock_api_keys, mock_insider_api):
        """Tests the function's error handling when the SEC API fails."""
        # Arrange

        mock_api_keys.sec_api_io_key = "fake_sec_key"
        mock_api_instance = mock_insider_api.return_value
        mock_api_instance.get_insider_transactions.side_effect = Exception(
            "Invalid API Key"
        )

        # Act

        result = track_insider_trading("AAPL")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("An API error occurred", result.error)
        self.assertIn("Invalid API Key", result.error)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.finint.track_insider_trading")
    def test_cli_insider_tracking_with_argument(self, mock_track_insider):
        """Tests the 'insider-tracking' command with a direct ticker argument."""
        # Arrange

        mock_track_insider.return_value = InsiderTradingResult(
            ticker="MSFT", total_transactions=5
        )

        # Act

        result = runner.invoke(finint_app, ["insider-tracking", "MSFT"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_track_insider.assert_called_with("MSFT")
        output = json.loads(result.stdout)
        self.assertEqual(output["ticker"], "MSFT")
        self.assertEqual(output["total_transactions"], 5)

    @patch("chimera_intel.core.finint.resolve_target")
    @patch("chimera_intel.core.finint.track_insider_trading")
    def test_cli_insider_tracking_with_project(
        self, mock_track_insider, mock_resolve_target
    ):
        """Tests the 'insider-tracking' command using an active project's ticker."""
        # Arrange

        mock_resolve_target.return_value = "GOOGL"
        mock_track_insider.return_value = InsiderTradingResult(
            ticker="GOOGL", total_transactions=10
        )

        # Act

        result = runner.invoke(finint_app, ["insider-tracking"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_resolve_target.assert_called_with(None, required_assets=["ticker"])
        mock_track_insider.assert_called_with("GOOGL")
        self.assertIn('"total_transactions": 10', result.stdout)

    @patch("chimera_intel.core.finint.resolve_target")
    def test_cli_insider_tracking_no_ticker(self, mock_resolve_target):
        """Tests CLI failure when no ticker is provided and no project is active."""
        # Arrange

        mock_resolve_target.side_effect = typer.Exit(code=1)

        # Act

        result = runner.invoke(finint_app, ["insider-tracking"])

        # Assert

        self.assertEqual(result.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
