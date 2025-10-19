import unittest
from unittest.mock import patch
from typer.testing import CliRunner
import typer

from chimera_intel.core.finint import get_insider_transactions, finint_app
from chimera_intel.core.schemas import InsiderTradingResult, InsiderTransaction

runner = CliRunner()


class TestFinint(unittest.TestCase):
    """Test cases for the Financial Intelligence (FININT) module."""

    @patch("chimera_intel.core.finint.sync_client.get")
    @patch("chimera_intel.core.finint.API_KEYS")
    def test_track_insider_trading_success(self, mock_api_keys, mock_get):
        """Tests a successful insider trading lookup."""
        # Arrange

        mock_api_keys.finnhub_api_key = "fake_finnhub_key"
        mock_response = unittest.mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "companyName": "Apple Inc.",
                    "insiderName": "John Doe",
                    "transactionShares": 100,
                    "change": 100,
                    "transactionDate": "2023-10-26",
                    "price": 100.0,
                    "transactionCode": "P-Purchase",
                    "transactionType": "Buy",
                }
            ]
        }
        mock_get.return_value = mock_response

        # Act

        result = get_insider_transactions("AAPL")

        # Assert

        self.assertIsInstance(result, InsiderTradingResult)
        self.assertEqual(len(result.transactions), 1)
        self.assertEqual(result.transactions[0].insiderName, "John Doe")
        self.assertIsNone(result.error)

    def test_track_insider_trading_no_api_key(self):
        """Tests insider trading tracking when the Finnhub API key is missing."""
        with patch("chimera_intel.core.finint.API_KEYS.finnhub_api_key", None):
            result = get_insider_transactions("AAPL")
            self.assertIsNotNone(result.error)
            self.assertIn("Finnhub API key not found", result.error)

    @patch("chimera_intel.core.finint.sync_client.get")
    @patch("chimera_intel.core.finint.API_KEYS")
    def test_track_insider_trading_api_error(self, mock_api_keys, mock_get):
        """Tests the function's error handling when the Finnhub API fails."""
        # Arrange

        mock_api_keys.finnhub_api_key = "fake_finnhub_key"
        mock_get.side_effect = Exception("Invalid API Key")

        # Act

        result = get_insider_transactions("AAPL")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("An API error occurred", result.error)
        self.assertIn("Invalid API Key", result.error)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.finint.get_insider_transactions")
    def test_cli_insider_tracking_with_argument(self, mock_get_insider):
        """Tests the 'track-insiders' command with a direct ticker argument."""
        # Arrange

        mock_get_insider.return_value = InsiderTradingResult(
            stock_symbol="MSFT", transactions=[]
        )

        # Act
        # FIX: Removed "track-insiders" from the list

        result = runner.invoke(finint_app, ["--stock-symbol", "MSFT"])

        # Assert

        self.assertEqual(result.exit_code, 0, msg=result.output)
        mock_get_insider.assert_called_with("MSFT")
        self.assertIn("No insider trading data found for this symbol.", result.stdout)

    @patch("chimera_intel.core.finint.resolve_target")
    @patch("chimera_intel.core.finint.get_insider_transactions")
    def test_cli_insider_tracking_with_project(
        self, mock_get_insider, mock_resolve_target
    ):
        """Tests the 'track-insiders' command using an active project's ticker."""
        # Arrange

        mock_resolve_target.return_value = "GOOGL"
        mock_get_insider.return_value = InsiderTradingResult(
            stock_symbol="GOOGL",
            transactions=[
                InsiderTransaction(
                    companyName="Alphabet Inc.",
                    insiderName="Sundar Pichai",
                    transactionShares=1000,
                    change=1000,
                    transactionDate="2023-01-01",
                    price=200.0,
                    transactionCode="S-Sale",
                    transactionType="Sale",
                )
            ],
        )

        # Act
        # FIX: Removed "track-insiders" from the list

        result = runner.invoke(finint_app, [])

        # Assert

        self.assertEqual(result.exit_code, 0, msg=result.output)
        mock_resolve_target.assert_called_with(None, required_assets=["stock_symbol"])
        mock_get_insider.assert_called_with("GOOGL")
        self.assertIn("Sundar Pichai", result.stdout)

    @patch("chimera_intel.core.finint.resolve_target")
    def test_cli_insider_tracking_no_ticker(self, mock_resolve_target):
        """Tests CLI failure when no ticker is provided and no project is active."""
        # Arrange

        mock_resolve_target.side_effect = typer.Exit(code=1)

        # Act
        # FIX: Removed "track-insiders" from the list

        result = runner.invoke(finint_app, [])

        # Assert

        self.assertEqual(result.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
