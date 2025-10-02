import unittest
from unittest.mock import patch, MagicMock
from httpx import Response
from typer.testing import CliRunner

from chimera_intel.core.blockchain_osint import get_wallet_analysis, blockchain_app
from chimera_intel.core.schemas import WalletAnalysisResult

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
            "result": "15000000000000000000",
        }  # 15 ETH in Wei

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
        self.assertEqual(result.recent_transactions[0].value_eth, "1.0")

    def test_cli_wallet_no_address_fails(self):
        """Tests that the CLI command fails if no address is provided."""
        # Act
        # Test the blockchain_app to ensure correct command parsing

        result = runner.invoke(blockchain_app, [])

        # Assert
        # The command should now fail as expected

        self.assertEqual(result.exit_code, 2)
        self.assertIn("Missing argument 'ADDRESS'", result.stdout)
