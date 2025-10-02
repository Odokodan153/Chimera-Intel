import unittest
from unittest.mock import patch, MagicMock
import asyncio

from chimera_intel.core.geoint import (
    generate_geoint_report,
    get_country_risk_data,
    _get_countries_from_ips,
)
from chimera_intel.core.schemas import GeointReport, CountryRiskProfile, GeoIntelData


class TestGeoint(unittest.TestCase):
    """Test cases for the geoint module."""

    @patch("chimera_intel.core.geoint.get_aggregated_data_for_target")
    @patch("chimera_intel.core.geoint.get_country_risk_data")
    @patch("chimera_intel.core.geoint.asyncio.run")
    def test_generate_geoint_report_success(
        self, mock_asyncio_run, mock_get_risk_data, mock_get_aggregated_data
    ):
        """Tests a successful GEOINT report generation."""
        mock_get_aggregated_data.return_value = {
            "modules": {
                "physical_osint_locations": {
                    "locations_found": [{"address": "123 Main St, Anytown, USA"}]
                },
                "footprint": {"dns_records": {"A": ["8.8.8.8"]}},
            }
        }
        mock_asyncio_run.return_value = {"USA"}
        mock_get_risk_data.return_value = CountryRiskProfile(
            country_name="USA", region="Americas"
        )

        result = generate_geoint_report("example.com")

        self.assertIsInstance(result, GeointReport)
        self.assertEqual(len(result.country_risk_profiles), 1)
        self.assertEqual(result.country_risk_profiles[0].country_name, "USA")

    @patch("chimera_intel.core.geoint.sync_client.get")
    def test_get_country_risk_data_success(self, mock_get):
        """Tests fetching country risk data."""
        mock_response_country = MagicMock()
        mock_response_country.json.return_value = [
            {
                "name": {"common": "Testland"},
                "cca2": "TL",
                "region": "Testregion",
                "subregion": "Testsubregion",
                "population": 1000,
            }
        ]
        mock_response_wb = MagicMock()
        mock_response_wb.json.return_value = [
            None,
            [{"value": 1.5}],
        ]
        mock_get.side_effect = [mock_response_country, mock_response_wb]

        result = get_country_risk_data("Testland")

        self.assertIsNotNone(result)
        self.assertEqual(result.country_name, "Testland")
        self.assertEqual(result.political_stability_index, 1.5)

    @patch("chimera_intel.core.geoint.get_geolocation_data", new_callable=MagicMock)
    def test_get_countries_from_ips(self, mock_get_geolocation_data):
        """Tests getting countries from a list of IP addresses."""

        async def mock_coro(ip):
            if ip == "8.8.8.8":
                return GeoIntelData(query="8.8.8.8", country="USA")
            return None

        mock_get_geolocation_data.side_effect = mock_coro

        async def run_test():
            return await _get_countries_from_ips(["8.8.8.8", "1.1.1.1"])

        countries = asyncio.run(run_test())
        self.assertEqual(countries, {"USA"})


if __name__ == "__main__":
    unittest.main()
