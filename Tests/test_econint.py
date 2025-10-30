import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from typer.testing import CliRunner
from chimera_intel.core.econint import app, get_macro_indicators, get_micro_indicators
from chimera_intel.core.schemas import MacroIndicators, MicroIndicators
import pandas as pd

runner = CliRunner()


class TestEconint(unittest.TestCase):
    """Test cases for the Economic Intelligence (ECONINT) module."""

    @patch("chimera_intel.core.econint.wbdata.get_countries")
    @patch("chimera_intel.core.econint.wbdata.get_dataframe")
    def test_get_macro_indicators_success(self, mock_get_dataframe, mock_get_countries):
        """Tests a successful macro indicators fetch."""
        mock_get_countries.return_value = [{"name": "United States"}]
        mock_df = pd.DataFrame(
            {
                "NY.GDP.MKTP.CD": [2.3e13],
                "FP.CPI.TOTL.ZG": [4.7],
                "SL.UEM.TOTL.ZS": [3.6],
            },
            index=["2022"],
        )
        mock_get_dataframe.return_value = mock_df

        result = get_macro_indicators("US")
        self.assertEqual(result.country, "United States")
        self.assertEqual(result.gdp_latest, 2.3e13)
        self.assertIsNone(result.error)

    @patch(
        "chimera_intel.core.econint.wbdata.get_countries",
        side_effect=Exception("API Error"),
    )
    def test_get_macro_indicators_api_error(self, mock_get_countries):
        """Tests the function's error handling when the World Bank API fails."""
        result = get_macro_indicators("US")
        self.assertIsInstance(result, MacroIndicators)
        self.assertEqual(result.country, "US")
        self.assertIsNotNone(result.error)
        self.assertIn("API Error", result.error)

    @patch("chimera_intel.core.econint.API_KEYS")
    @patch("chimera_intel.core.econint.httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_get_micro_indicators_success(self, mock_get, mock_api_keys):
        """Tests a successful micro indicators fetch."""
        mock_api_keys.alpha_vantage_api_key = "fake_key"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "Symbol": "AAPL",
            "LastPrice": "150.0",
            "MarketCapitalization": "2500000000000",
            "PERatio": "25.5",
        }
        mock_get.return_value = mock_response

        result = await get_micro_indicators("AAPL")
        self.assertEqual(result.symbol, "AAPL")
        self.assertEqual(result.latest_price, 150.0)
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.econint.get_macro_indicators")
    def test_cli_macro_success(self, mock_get_macro_indicators):
        """Tests the CLI macro command."""
        mock_get_macro_indicators.return_value = MacroIndicators(
            country="United States",
            gdp_latest=2.3e13,
            inflation_latest=4.7,
            unemployment_latest=3.6,
        )
        result = runner.invoke(app, ["macro", "US"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Macroeconomic Indicators for United States", result.stdout)
        self.assertIn("GDP (current US$)", result.stdout)

    @patch("chimera_intel.core.econint.get_micro_indicators")
    def test_cli_micro_success(self, mock_get_micro_indicators):
        """Tests the CLI micro command."""
        mock_get_micro_indicators.return_value = MicroIndicators(
            symbol="AAPL", latest_price=150.0, market_cap="2.5T", pe_ratio=25.5
        )
        result = runner.invoke(app, ["micro", "AAPL"])
        self.assertEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
