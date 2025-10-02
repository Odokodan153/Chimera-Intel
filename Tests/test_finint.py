import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
import typer

from chimera_intel.core.finint import track_insider_trading, finint_app
from chimera_intel.core.schemas import InsiderTradingResult

runner = CliRunner()


class TestFinint(unittest.TestCase):
    """Test cases for the Financial Intelligence (FININT) module."""

    @patch("chimera_intel.core.finint.API_KEYS")
    @patch("chimera_intel.core.finint.InsiderTradingApi")
    def test_track_insider_trading_success(self, mock_insider_api, mock_api_keys):
        """Tests a successful insider trading lookup."""
        # Arrange

        mock_api_keys.sec_api_io_key = "fake_sec_key"
        mock_api_instance = mock_insider_api.return_value
        mock_api_instance.get_insider_transactions.return_value = {
            "total": 1,
            "transactions": [
                {
                    "companyName": "Apple Inc",
                    "insiderName": "Tim Cook",
                    "transactionType": "P-Purchase",
                    "transactionDate": "2025-01-15",
                    "shares": 1000,
                    "value": 150000,
                }
            ],
        }

        # Act

        result = track_insider_trading("AAPL")

        # Assert

        self.assertIsInstance(result, InsiderTradingResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_transactions, 1)
        self.assertEqual(len(result.transactions), 1)
        self.assertEqual(result.transactions[0].insiderName, "Tim Cook")
        mock_insider_api.assert_called_with(api_key="fake_sec_key")

    @patch("chimera_intel.core.finint.API_KEYS")
    def test_track_insider_trading_no_api_key(self, mock_api_keys):
        """Tests the function when the SEC API key is missing."""
        # Arrange

        mock_api_keys.sec_api_io_key = None

        # Act

        result = track_insider_trading("AAPL")

        # Assert

        self.assertIsInstance(result, InsiderTradingResult)
        self.assertIsNotNone(result.error)
        self.assertIn("key not found", result.error)

    @patch("chimera_intel.core.finint.API_KEYS")
    @patch("chimera_intel.core.finint.InsiderTradingApi")
    def test_track_insider_trading_api_error(self, mock_insider_api, mock_api_keys):
        """Tests the function's error handling when the API call fails."""
        # Arrange

        mock_api_keys.sec_api_io_key = "fake_sec_key"
        mock_api_instance = mock_insider_api.return_value
        mock_api_instance.get_insider_transactions.side_effect = Exception(
            "API limit reached"
        )

        # Act

        result = track_insider_trading("AAPL")

        # Assert

        self.assertIsInstance(result, InsiderTradingResult)
        self.assertIsNotNone(result.error)
        self.assertIn("API error occurred", result.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.finint.resolve_target")
    @patch("chimera_intel.core.finint.track_insider_trading")
    def test_cli_insider_tracking_with_project(
        self, mock_track_insider, mock_resolve_target
    ):
        """Tests the 'finint insider-tracking' command using the centralized resolver."""
        # Arrange

        mock_resolve_target.return_value = "PRJT"
        # Mock the entire model and its dump method

        mock_track_insider.return_value = MagicMock()
        mock_track_insider.return_value.model_dump.return_value = {"ticker": "PRJT"}

        # Act
        # FIX: When a Typer app has a single command that takes an optional argument,
        # invoking it with no arguments should not pass any strings to the runner.

        result = runner.invoke(finint_app, [])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_resolve_target.assert_called_with(None, required_assets=["ticker"])
        mock_track_insider.assert_called_with("PRJT")

    @patch("chimera_intel.core.finint.resolve_target")
    def test_cli_insider_tracking_resolver_fails(self, mock_resolve_target):
        """Tests CLI failure when the resolver raises an exit exception."""
        # Arrange

        mock_resolve_target.side_effect = typer.Exit(code=1)

        # Act
        # FIX: Correct invocation for a command with an optional argument being omitted.

        result = runner.invoke(finint_app, [])

        # Assert

        self.assertEqual(result.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
