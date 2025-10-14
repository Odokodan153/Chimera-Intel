import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from typer.testing import CliRunner
from chimera_intel.core.econint import app as econint_app
from chimera_intel.core.econint import (
    get_economic_indicators,
    EconomicIndicators,
    get_macro_indicators, 
    get_micro_indicators
)
import pandas as pd
import json

runner = CliRunner()


class TestEconint(unittest.TestCase):
    """Test cases for the Economic Intelligence (ECONINT) module."""

    @patch("wbgapi.data.DataFrame")
    def test_get_economic_indicators_success(self, mock_wb_data):
        """Tests a successful economic indicators lookup."""
        # Arrange

        mock_wb_data.return_value = pd.DataFrame(
            {
                "NY.GDP.MKTP.CD": [2.1433226e13],
                "NY.GDP.MKTP.KD.ZG": [2.926995],
                "FP.CPI.TOTL.ZG": [1.812210],
                "SL.UEM.TOTL.ZS": [3.668000],
            },
            index=["USA"],
        )

        # Act

        result = get_economic_indicators("US")

        # Assert

        self.assertIsInstance(result, EconomicIndicators)
        self.assertEqual(result.country, "US")
        self.assertIn("GDP (current US$)", result.indicators)
        self.assertIn("GDP growth (annual %)", result.indicators)
        self.assertIn("Inflation, consumer prices (annual %)", result.indicators)
        self.assertIn("Unemployment, total (% of total labor force)", result.indicators)
        self.assertIsNone(result.error)

    @patch("wbgapi.data.DataFrame", side_effect=Exception("API Error"))
    def test_get_economic_indicators_api_error(self, mock_wb_data):
        """Tests the function's error handling when the World Bank API fails."""
        # Act

        result = get_economic_indicators("US")

        # Assert

        self.assertIsInstance(result, EconomicIndicators)
        self.assertEqual(result.country, "US")
        self.assertIsNotNone(result.error)
        self.assertIn("An API error occurred: API Error", result.error)

    @patch("wbgapi.data.DataFrame")
    def test_get_economic_indicators_no_data(self, mock_wb_data):
        """Tests the function's handling of no data."""
        # Arrange

        mock_wb_data.return_value = pd.DataFrame()

        # Act

        result = get_economic_indicators("US")

        # Assert

        self.assertIsInstance(result, EconomicIndicators)
        self.assertEqual(result.country, "US")
        self.assertIsNotNone(result.error)
        self.assertEqual(result.error, "No data available for the selected country.")

    @patch("chimera_intel.core.econint.get_economic_indicators")
    def test_cli_indicators_success(self, mock_get_indicators):
        """Tests the CLI indicators command."""
        # Arrange

        mock_get_indicators.return_value = EconomicIndicators(
            country="US", indicators={"GDP (current US$)": 2.1433226e13}
        )

        # Act

        result = runner.invoke(econint_app, ["indicators", "US"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_get_indicators.assert_called_with("US")
        output = json.loads(result.stdout)
        self.assertEqual(output["country"], "US")
        self.assertIn("indicators", output)
        
    @patch("chimera_intel.core.economic_engine.wbdata.get_countries")
    @patch("chimera_intel.core.economic_engine.wbdata.get_dataframe")
    def test_get_macro_indicators_success(self, mock_get_dataframe, mock_get_countries):
        """Tests a successful macro indicators fetch."""
        mock_get_countries.return_value = [{'name': 'United States'}]
        mock_df = pd.DataFrame({
            "NY.GDP.MKTP.CD": [2.3e13],
            "FP.CPI.TOTL.ZG": [4.7],
            "SL.UEM.TOTL.ZS": [3.6]
        }, index=["2022"])
        mock_get_dataframe.return_value = mock_df

        result = get_macro_indicators("US")
        self.assertEqual(result.country, "United States")
        self.assertEqual(result.gdp_latest, 2.3e13)
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.economic_engine.API_KEYS")
    @patch("chimera_intel.core.economic_engine.httpx.AsyncClient.get", new_callable=AsyncMock)
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


if __name__ == "__main__":
    unittest.main()
