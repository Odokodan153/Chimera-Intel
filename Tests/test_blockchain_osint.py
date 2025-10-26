import unittest
from unittest.mock import patch, MagicMock
from httpx import Response, RequestError, HTTPStatusError
from typer.testing import CliRunner

# Import the main app creator and the blockchain subcommand app
from chimera_intel.cli import get_cli_app
from chimera_intel.core.blockchain_osint import blockchain_app as blockchain_plugin_app
from chimera_intel.core.blockchain_osint import get_wallet_analysis
from chimera_intel.core.schemas import WalletAnalysisResult, WalletTransaction

# Create a runner
runner = CliRunner()

# Create the main app instance for testing
app = get_cli_app()
# Manually add the blockchain app as a subcommand, as the plugin discovery won't run
app.add_typer(blockchain_plugin_app, name="blockchain")


class TestBlockchainOsint(unittest.TestCase):
    """Test cases for the blockchain_osint module."""

    @patch("chimera_intel.core.blockchain_osint.API_KEYS")
    @patch("chimera_intel.core.blockchain_osint.sync_client.get")
    def test_get_wallet_analysis_success(self, mock_get, mock_api_keys):
        """Tests a successful wallet analysis by mocking the Etherscan API."""
        # Arrange
        mock_api_keys.etherscan_api_key = "fake_etherscan_key"

        # Simulate Balance API response
        mock_balance_response = MagicMock(spec=Response)
        mock_balance_response.raise_for_status.return_value = None
        mock_balance_response.json.return_value = {
            "status": "1",
            "result": "15000000000000000000",  # 15 ETH in Wei
        }

        # Simulate Transaction API response
        mock_tx_response = MagicMock(spec=Response)
        mock_tx_response.raise_for_status.return_value = None
        mock_tx_response.json.return_value = {
            "status": "1",
            "result": [
                {
                    "hash": "0x123...",
                    "from": "0xabc...",
                    "to": "0xdef...",
                    "value": "1000000000000000000",
                    "timeStamp": "1672531200",
                }
            ],
        }

        mock_get.side_effect = [mock_balance_response, mock_tx_response]

        # Act
        result = get_wallet_analysis("0x123abc")

        # Assert
        self.assertIsInstance(result, WalletAnalysisResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.balance_eth, "15.0000")
        self.assertEqual(len(result.recent_transactions), 1)
        self.assertIsInstance(result.recent_transactions[0], WalletTransaction)
        self.assertEqual(result.recent_transactions[0].value_eth, "1.0")

    def test_get_wallet_analysis_no_api_key(self):
        """Tests the function's behavior when the Etherscan API key is missing."""
        with patch(
            "chimera_intel.core.blockchain_osint.API_KEYS.etherscan_api_key", None
        ):
            result = get_wallet_analysis("0x123abc")
            self.assertIsNotNone(result.error)
            self.assertIn("Etherscan API key not found", result.error)

    @patch("chimera_intel.core.blockchain_osint.API_KEYS")
    @patch("chimera_intel.core.blockchain_osint.sync_client.get")
    def test_get_wallet_analysis_api_error(self, mock_get, mock_api_keys):
        """Tests the function's error handling when the Etherscan API fails."""
        # Arrange
        mock_api_keys.etherscan_api_key = "fake_etherscan_key"
        mock_get.side_effect = RequestError("Service Unavailable")

        # Act
        result = get_wallet_analysis("0x123abc")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("An API error occurred", result.error)

    # --- Extended Test ---
    @patch("chimera_intel.core.blockchain_osint.API_KEYS")
    @patch("chimera_intel.core.blockchain_osint.sync_client.get")
    def test_get_wallet_analysis_http_error(self, mock_get, mock_api_keys):
        """Tests the function's error handling for an HTTP 500 error."""
        # Arrange
        mock_api_keys.etherscan_api_key = "fake_etherscan_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.side_effect = HTTPStatusError(
            "Server Error", request=MagicMock(), response=MagicMock(status_code=500)
        )
        mock_get.return_value = mock_response

        # Act
        result = get_wallet_analysis("0x123abc")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("An API error occurred", result.error)

    # --- Extended Test ---
    @patch("chimera_intel.core.blockchain_osint.API_KEYS")
    @patch("chimera_intel.core.blockchain_osint.sync_client.get")
    def test_get_wallet_analysis_bad_json_response(self, mock_get, mock_api_keys):
        """Tests the function's error handling for a malformed JSON response."""
        # Arrange
        mock_api_keys.etherscan_api_key = "fake_etherscan_key"

        mock_balance_response = MagicMock(spec=Response)
        mock_balance_response.raise_for_status.return_value = None
        # Malformed response (missing 'result')
        mock_balance_response.json.return_value = {"status": "1"}
        mock_get.return_value = mock_balance_response

        # Act
        result = get_wallet_analysis("0x123abc")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("An API error occurred", result.error)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.blockchain_osint.save_scan_to_db")
    @patch("chimera_intel.core.blockchain_osint.save_or_print_results")
    @patch("chimera_intel.core.blockchain_osint.get_wallet_analysis")
    def test_cli_wallet_success(self, mock_get_analysis, mock_save_print, mock_save_db):
        """Tests a successful run of the 'analyze' CLI command."""
        # Arrange
        mock_get_analysis.return_value = WalletAnalysisResult(
            address="0x123abc",
            balance_eth="15.0000",
            total_transactions=1,
            recent_transactions=[],
        )

        # Act
        result = runner.invoke(app, ["blockchain", "analyze", "0x123abc"])

        # Assert
        self.assertEqual(result.exit_code, 0, result.stderr)
        mock_save_print.assert_called_once()
        mock_get_analysis.assert_called_once_with("0x123abc")
        mock_save_db.assert_called_once()
        # Check that the output file was None
        self.assertIsNone(mock_save_print.call_args[0][1])

    def test_cli_wallet_no_address_fails(self):
        """
        Tests that the CLI command fails correctly if no address is provided.
        """
        # Act
        result = runner.invoke(app, ["blockchain", "analyze"])

        # Assert
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Missing argument 'ADDRESS'", result.stderr)

    # --- Extended Test ---
    @patch("chimera_intel.core.blockchain_osint.save_scan_to_db")
    @patch("chimera_intel.core.blockchain_osint.save_or_print_results")
    @patch("chimera_intel.core.blockchain_osint.get_wallet_analysis")
    def test_cli_wallet_with_output_file(
        self, mock_get_analysis, mock_save_print, mock_save_db
    ):
        """Tests the CLI command with an --output file."""
        # Arrange
        mock_dump_dict = {"address": "0x123abc"}
        mock_get_analysis.return_value = MagicMock(
            model_dump=lambda exclude_none: mock_dump_dict
        )

        # Act
        result = runner.invoke(
            app, ["blockchain", "analyze", "0x123abc", "--output", "wallet.json"]
        )

        # Assert
        self.assertEqual(result.exit_code, 0, result.stderr)
        mock_get_analysis.assert_called_once_with("0x123abc")
        # Check that save_or_print_results was called with the output file
        mock_save_print.assert_called_with(mock_dump_dict, "wallet.json")
        mock_save_db.assert_called_once()


if __name__ == "__main__":
    unittest.main()