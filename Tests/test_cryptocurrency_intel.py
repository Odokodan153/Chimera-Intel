import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from chimera_intel.core.cryptocurrency_intel import (
    get_crypto_data,
    get_crypto_forecast,
    CryptoData,
)


class TestCryptocurrencyIntel(unittest.TestCase):
    """Test cases for the cryptocurrency_intel module."""

    @patch("chimera_intel.core.cryptocurrency_intel.API_KEYS")
    @patch(
        "chimera_intel.core.cryptocurrency_intel.httpx.AsyncClient.get",
        new_callable=AsyncMock,
    )
    async def test_get_crypto_data_success(self, mock_get, mock_api_keys):
        """Tests a successful crypto data fetch."""
        mock_api_keys.alpha_vantage_api_key = "fake_key"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "Time Series (Digital Currency Daily)": {
                "2025-01-01": {"4a. close (USD)": "50000.0"},
                "2025-01-02": {"4a. close (USD)": "51000.0"},
            }
        }
        mock_get.return_value = mock_response

        result = await get_crypto_data("BTC", "USD")
        self.assertIsNotNone(result.history)
        self.assertIsNone(result.error)

    def test_get_crypto_forecast_success(self):
        """Tests a successful crypto forecast."""
        history = {
            "2025-01-01": {"4a. close (USD)": "50000.0"},
            "2025-01-02": {"4a. close (USD)": "51000.0"},
            "2025-01-03": {"4a. close (USD)": "52000.0"},
            "2025-01-04": {"4a. close (USD)": "53000.0"},
            "2025-01-05": {"4a. close (USD)": "54000.0"},
            "2025-01-06": {"4a. close (USD)": "55000.0"},
        }
        crypto_data = CryptoData(symbol="BTC", market="USD", history=history)

        result = get_crypto_forecast(crypto_data, 7)
        self.assertIsNotNone(result.forecast)
        self.assertEqual(len(result.forecast), 7)
        self.assertIsNone(result.error)


if __name__ == "__main__":
    unittest.main()
