import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner
import typer

from chimera_intel.core.geoint import (
    get_country_risk_data,
    generate_geoint_report,
    geoint_app,
)
from chimera_intel.core.schemas import (
    GeointReport,
    CountryRiskProfile
)

runner = CliRunner()


class TestGeoint(unittest.IsolatedAsyncioTestCase):
    """Test cases for the Geopolitical Intelligence (GEOINT) module."""

    # --- Function Tests ---

    @patch("chimera_intel.core.geoint.sync_client.get")
    def test_get_country_risk_data_success(self, mock_get):
        """Tests a successful country risk data lookup."""
        # Arrange

        mock_country_response = MagicMock()
        mock_country_response.raise_for_status.return_value = None
        mock_country_response.json.return_value = [
            {
                "name": {"common": "United States"},
                "cca2": "US",
                "region": "Americas",
                "population": 331000000,
            }
        ]

        mock_wb_response = MagicMock()
        mock_wb_response.raise_for_status.return_value = None
        mock_wb_response.json.return_value = [
            None,
            [{"value": 0.5}],
        ]  # World Bank API format

        mock_get.side_effect = [mock_country_response, mock_wb_response]

        # Act

        result = get_country_risk_data("United States")

        # Assert

        self.assertIsInstance(result, CountryRiskProfile)
        self.assertEqual(result.country_name, "United States")
        self.assertEqual(result.political_stability_index, 0.5)

    @patch("chimera_intel.core.geoint.get_aggregated_data_for_target")
    @patch("chimera_intel.core.geoint._get_countries_from_ips", new_callable=AsyncMock)
    @patch("chimera_intel.core.geoint.get_country_risk_data")
    def test_generate_geoint_report_success(
        self, mock_get_risk, mock_get_ips, mock_get_agg_data
    ):
        """Tests the successful generation of a GEOINT report."""
        # Arrange

        mock_get_agg_data.return_value = {
            "modules": {
                "physical_osint_locations": {
                    "locations_found": [{"address": "Somewhere, USA"}]
                },
                "footprint": {"dns_records": {"A": ["1.1.1.1"]}},
            }
        }
        mock_get_ips.return_value = {"Canada"}
        mock_get_risk.return_value = CountryRiskProfile(country_name="Canada")

        # Act

        report = generate_geoint_report("example.com")

        # Assert

        self.assertIsInstance(report, GeointReport)
        self.assertEqual(len(report.country_risk_profiles), 1)
        self.assertEqual(report.country_risk_profiles[0].country_name, "Canada")
        self.assertIsNone(report.error)

    def test_generate_geoint_report_no_data(self):
        """Tests report generation when no historical data is available."""
        with patch(
            "chimera_intel.core.geoint.get_aggregated_data_for_target",
            return_value=None,
        ):
            report = generate_geoint_report("example.com")
            self.assertIsNotNone(report.error)
            self.assertIn("No historical data", report.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.geoint.resolve_target")
    @patch("chimera_intel.core.geoint.generate_geoint_report")
    def test_cli_run_geoint_analysis_success(self, mock_generate, mock_resolve):
        """Tests a successful run of the 'geoint run' CLI command."""
        # Arrange

        mock_resolve.return_value = "example.com"
        mock_generate.return_value = GeointReport(
            target="example.com",
            country_risk_profiles=[CountryRiskProfile(country_name="Testland")],
        )

        # Act

        result = runner.invoke(geoint_app, ["run"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_resolve.assert_called_with(
            None, required_assets=["company_name", "domain"]
        )
        mock_generate.assert_called_with("example.com")
        self.assertIn('"country_name": "Testland"', result.stdout)

    @patch("chimera_intel.core.geoint.resolve_target")
    def test_cli_run_geoint_analysis_no_target(self, mock_resolve):
        """Tests CLI failure when no target can be resolved."""
        # Arrange

        mock_resolve.side_effect = typer.Exit(code=1)

        # Act

        result = runner.invoke(geoint_app, ["run"])

        # Assert

        self.assertEqual(result.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
