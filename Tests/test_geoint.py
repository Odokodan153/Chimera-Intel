import unittest
from unittest.mock import patch

from chimera_intel.core.geoint import generate_geoint_report
from chimera_intel.core.schemas import GeointReport, CountryRiskProfile


class TestGeoint(unittest.TestCase):
    """Test cases for the Geopolitical Intelligence (GEOINT) module."""

    @patch("chimera_intel.core.geoint.get_country_risk_data")
    @patch("chimera_intel.core.geoint.get_aggregated_data_for_target")
    def test_generate_geoint_report_success(self, mock_get_agg_data, mock_get_risk):
        """Tests a successful GEOINT report generation."""
        # Arrange: Mock the database to return a physical location

        mock_get_agg_data.return_value = {
            "modules": {
                "physical_osint_locations": {
                    "locations_found": [
                        {"address": "123 Main St, Anytown, United States"}
                    ]
                }
            }
        }
        # Mock the risk API to return a profile for the found country

        mock_get_risk.return_value = CountryRiskProfile(
            country_name="United States",
            region="Americas",
            political_stability_index=7.2,
        )

        # Act

        result = generate_geoint_report("TestCorp")

        # Assert

        self.assertIsInstance(result, GeointReport)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.country_risk_profiles), 1)
        self.assertEqual(result.country_risk_profiles[0].country_name, "United States")
        mock_get_risk.assert_called_once_with("United States")

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
