import unittest
from unittest.mock import patch, MagicMock
from httpx import Response, RequestError
from typer.testing import CliRunner
import json

from chimera_intel.core.blockchain_osint import get_wallet_analysis, blockchain_app
from chimera_intel.core.schemas import WalletAnalysisResult, WalletTransaction

runner = CliRunner()


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

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.blockchain_osint.get_wallet_analysis")
    def test_cli_wallet_success(self, mock_get_analysis):
        """Tests a successful run of the 'analyze' CLI command."""
        # Arrange

        mock_get_analysis.return_value = WalletAnalysisResult(
            address="0x123abc",
            balance_eth="15.0000",
            total_transactions=1,
            recent_transactions=[],
        )

        # Act

        result = runner.invoke(blockchain_app, ["analyze", "0x123abc"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["address"], "0x123abc")
        self.assertEqual(output["balance_eth"], "15.0000")

    def test_cli_wallet_no_address_fails(self):
        """
        CORRECTED: Tests that the CLI command fails correctly if no address is provided.
        Typer exits with code 2 for missing arguments.
        """
        # Act

        result = runner.invoke(blockchain_app, ["analyze"])

        # Assert

        self.assertEqual(result.exit_code, 2)
        self.assertIn("Missing argument 'ADDRESS'", result.stdout)


if __name__ == "__main__":
    unittest.main()
