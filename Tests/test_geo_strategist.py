import unittest
from unittest.mock import patch
from typer.testing import CliRunner
import typer

# Import the specific Typer app for this module, not the main one


from chimera_intel.core.geo_strategist import geo_strategist_app
from chimera_intel.core.geo_strategist import generate_geo_strategic_report
from chimera_intel.core.schemas import GeoStrategicReport

runner = CliRunner()


class TestGeoStrategist(unittest.TestCase):
    """Test cases for the Geo-Strategist module."""

    @patch("chimera_intel.core.geo_strategist.get_aggregated_data_for_target")
    def test_generate_geo_strategic_report_success(self, mock_get_data):
        """Tests successful report generation from various data sources."""
        # Arrange: Provide a rich mock data structure
        # FIX: The 'name' of the physical location and the 'location' of the hiring
        # data are now the same ('Techville') to test the data synthesis logic.

        mock_get_data.return_value = {
            "target": "TestCorp",
            "modules": {
                "physical_osint_locations": {
                    "locations_found": [
                        {
                            "name": "Techville",
                            "address": "123 Innovation Drive, Techville",
                            "rating": 4.5,
                        }
                    ]
                },
                "corporate_hr_intel": {
                    "hiring_trends": {
                        "job_postings": [
                            {"title": "Software Engineer", "location": "Techville"}
                        ]
                    }
                },
                "ecosystem_analysis": {
                    "ecosystem_data": {
                        "distributors": [
                            {
                                "distributor_name": "Global Logistics Inc.",
                                "location": "Port City",
                            }
                        ]
                    }
                },
            },
        }

        # Act

        result = generate_geo_strategic_report("TestCorp")

        # Assert

        self.assertIsInstance(result, GeoStrategicReport)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.operational_centers), 2)

        # Find the Techville center and check for synthesized data

        techville_center = next(
            (
                c
                for c in result.operational_centers
                if "techville" in c.location_name.lower()
            ),
            None,
        )
        self.assertIsNotNone(techville_center)
        self.assertIn("physical_osint", techville_center.source_modules)
        self.assertIn("corporate_hr_intel", techville_center.source_modules)
        self.assertIn("Hiring for", techville_center.details)

        # Check for the Port City distributor hub

        port_city_center = next(
            (
                c
                for c in result.operational_centers
                if "port city" in c.location_name.lower()
            ),
            None,
        )
        self.assertIsNotNone(port_city_center)
        self.assertEqual(
            port_city_center.location_type, "Supply Chain / Distribution Hub"
        )

    @patch("chimera_intel.core.geo_strategist.get_aggregated_data_for_target")
    def test_generate_report_no_data(self, mock_get_data):
        """Tests the function's response when no historical data is available."""
        # Arrange

        mock_get_data.return_value = None

        # Act

        result = generate_geo_strategic_report("NoDataCorp")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("Not enough historical data", result.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.geo_strategist.resolve_target")
    @patch("chimera_intel.core.geo_strategist.generate_geo_strategic_report")
    def test_cli_geo_strategist_with_project(
        self, mock_generate_report, mock_resolve_target
    ):
        """Tests the CLI command using the centralized target resolver."""
        # Arrange

        mock_resolve_target.return_value = "project-geo.com"
        mock_generate_report.return_value.model_dump.return_value = {}

        # Act
        # FIX: When a command takes an optional argument, invoking the runner with
        # no arguments correctly simulates a user not providing one.

        result = runner.invoke(geo_strategist_app, [])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_resolve_target.assert_called_with(
            None, required_assets=["domain", "company_name"]
        )
        mock_generate_report.assert_called_with("project-geo.com")

    @patch("chimera_intel.core.geo_strategist.resolve_target")
    def test_cli_geo_strategist_resolver_fails(self, mock_resolve_target):
        """Tests CLI failure when the resolver raises an exit exception."""
        # Arrange

        mock_resolve_target.side_effect = typer.Exit(code=1)

        # Act
        # FIX: Correct invocation when no argument is provided.

        result = runner.invoke(geo_strategist_app, [])

        # Assert

        self.assertEqual(result.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
