import unittest
from unittest.mock import patch

from chimera_intel.core.geoint import generate_geoint_report
from chimera_intel.core.schemas import GeointReport, CountryRiskProfile


class TestGeoint(unittest.TestCase):
    """Test cases for the Geopolitical Intelligence (GEOINT) module."""

    @patch("chimera_intel.core.geoint.asyncio.run")
    @patch("chimera_intel.core.geoint.get_country_risk_data")
    @patch("chimera_intel.core.geoint.get_aggregated_data_for_target")
    def test_generate_geoint_report_success(
        self, mock_get_agg_data, mock_get_risk, mock_asyncio_run
    ):
        """Tests a successful GEOINT report generation with both physical and IP-based locations."""
        # Arrange: Mock the database to return a physical location and footprint data with an IP

        mock_get_agg_data.return_value = {
            "modules": {
                "physical_osint_locations": {
                    "locations_found": [
                        {"address": "123 Main St, Anytown, United States"}
                    ]
                },
                "footprint": {"dns_records": {"A": ["8.8.8.8"]}},
            }
        }
        # Mock the async call to get countries from IPs

        mock_asyncio_run.return_value = {"Canada"}

        # Mock the risk API to return profiles for the found countries

        def get_risk_side_effect(country_name):
            if country_name == "United States":
                return CountryRiskProfile(
                    country_name="United States",
                    region="Americas",
                    population=331000000,
                    political_stability_index=1.2,
                )
            if country_name == "Canada":
                return CountryRiskProfile(
                    country_name="Canada",
                    region="Americas",
                    population=38000000,
                    political_stability_index=1.5,
                )
            return None

        mock_get_risk.side_effect = get_risk_side_effect

        # Act

        result = generate_geoint_report("TestCorp")

        # Assert

        self.assertIsInstance(result, GeointReport)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.country_risk_profiles), 2)

        profile_names = {p.country_name for p in result.country_risk_profiles}
        self.assertIn("United States", profile_names)
        self.assertIn("Canada", profile_names)

        mock_asyncio_run.assert_called_once()
        self.assertEqual(mock_get_risk.call_count, 2)

    @patch("chimera_intel.core.geoint.get_aggregated_data_for_target")
    def test_generate_geoint_report_no_data(self, mock_get_agg_data):
        """Tests the report generation when no historical data is available."""
        # Arrange

        mock_get_agg_data.return_value = None

        # Act

        result = generate_geoint_report("TestCorp")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("No historical data found", result.error)


if __name__ == "__main__":
    unittest.main()
