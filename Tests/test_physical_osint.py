import unittest
from unittest.mock import patch
from typer.testing import CliRunner
import typer

from chimera_intel.core.physical_osint import (
    find_physical_locations,
    physical_osint_app,
)
from chimera_intel.core.schemas import PhysicalSecurityResult

runner = CliRunner()


class TestPhysicalOsint(unittest.TestCase):
    """Test cases for the physical_osint module."""

    @patch("chimera_intel.core.physical_osint.API_KEYS")
    @patch("chimera_intel.core.physical_osint.googlemaps.Client")
    def test_find_physical_locations_success(self, mock_gmaps_client, mock_api_keys):
        """Tests a successful location search by mocking the Google Maps API."""
        # Arrange

        mock_api_keys.google_maps_api_key = "fake_gmaps_key"
        mock_gmaps = mock_gmaps_client.return_value
        mock_gmaps.places.return_value = {
            "results": [
                {
                    "name": "Googleplex",
                    "formatted_address": "1600 Amphitheatre Pkwy, Mountain View, CA",
                    "geometry": {"location": {"lat": 37.422, "lng": -122.084}},
                    "rating": 4.5,
                }
            ]
        }

        # Act

        result = find_physical_locations("Googleplex")

        # Assert

        self.assertIsInstance(result, PhysicalSecurityResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.locations_found), 1)
        self.assertEqual(result.locations_found[0].name, "Googleplex")
        self.assertEqual(result.locations_found[0].latitude, 37.422)

    # --- CLI Tests ---

    @patch("chimera_intel.core.physical_osint.resolve_target")
    @patch("chimera_intel.core.physical_osint.find_physical_locations")
    def test_cli_locations_with_project(self, mock_find_locations, mock_resolve_target):
        """Tests the CLI command using the centralized target resolver."""
        # Arrange

        mock_resolve_target.return_value = "Project Corp"
        mock_find_locations.return_value.model_dump.return_value = {}

        # Act
        # Corrected: Invoke the command without any arguments.
        # This simulates a user running `chimera physical locations`
        # and relying on the active project context.

        result = runner.invoke(physical_osint_app, [])

        # Assert

        self.assertEqual(result.exit_code, 0)
        # The first argument to resolve_target should now be None, as expected.

        mock_resolve_target.assert_called_with(
            None, required_assets=["company_name", "domain"]
        )
        mock_find_locations.assert_called_with("Project Corp")

    @patch("chimera_intel.core.physical_osint.resolve_target")
    def test_cli_locations_resolver_fails(self, mock_resolve_target):
        """Tests CLI failure when the resolver raises an exit exception."""
        # Arrange

        mock_resolve_target.side_effect = typer.Exit(code=1)

        # Act

        result = runner.invoke(physical_osint_app, [])

        # Assert

        self.assertEqual(result.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
