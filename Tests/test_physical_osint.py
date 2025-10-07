import unittest
import json
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.physical_osint import (
    find_physical_locations,
    physical_osint_app,
)
from chimera_intel.core.schemas import (
    PhysicalSecurityResult,
    PhysicalLocation,
    ProjectConfig,
)

runner = CliRunner()


class TestPhysicalOsint(unittest.TestCase):
    """Test cases for the Physical Security OSINT module."""

    # --- Function Tests ---

    @patch("chimera_intel.core.physical_osint.googlemaps.Client")
    @patch("chimera_intel.core.physical_osint.API_KEYS")
    def test_find_physical_locations_success(self, mock_api_keys, mock_gmaps_client):
        """Tests a successful search for physical locations."""
        # Arrange

        mock_api_keys.google_maps_api_key = "fake_gmaps_key"
        mock_client_instance = mock_gmaps_client.return_value
        mock_client_instance.places.return_value = {
            "results": [
                {
                    "name": "Googleplex",
                    "formatted_address": "1600 Amphitheatre Parkway, Mountain View, CA",
                    "geometry": {"location": {"lat": 37.422, "lng": -122.084}},
                    "rating": 4.6,
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

    def test_find_physical_locations_no_api_key(self):
        """Tests the function's behavior when the API key is missing."""
        with patch(
            "chimera_intel.core.physical_osint.API_KEYS.google_maps_api_key", None
        ):
            result = find_physical_locations("Googleplex")
            self.assertIsNotNone(result.error)
            self.assertIn("Google Maps API key not found", result.error)

    @patch("chimera_intel.core.physical_osint.googlemaps.Client")
    @patch("chimera_intel.core.physical_osint.API_KEYS")
    def test_find_physical_locations_api_error(self, mock_api_keys, mock_gmaps_client):
        """Tests the function's error handling when the Google Maps API fails."""
        # Arrange

        mock_api_keys.google_maps_api_key = "fake_gmaps_key"
        mock_client_instance = mock_gmaps_client.return_value
        mock_client_instance.places.side_effect = Exception("API Request Denied")

        # Act

        result = find_physical_locations("Googleplex")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("An API error occurred", result.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.physical_osint.find_physical_locations")
    def test_cli_locations_with_argument(self, mock_find_locations):
        """Tests the 'locations' command with a direct argument."""
        # Arrange

        mock_find_locations.return_value = PhysicalSecurityResult(
            query="Test Corp",
            locations_found=[
                PhysicalLocation(
                    name="HQ", address="123 Main St", latitude=0, longitude=0
                )
            ],
        )

        # Act

        result = runner.invoke(physical_osint_app, ["locations", "Test Corp"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_find_locations.assert_called_with("Test Corp")
        output = json.loads(result.stdout)
        self.assertEqual(output["query"], "Test Corp")
        self.assertEqual(len(output["locations_found"]), 1)

    @patch("chimera_intel.core.physical_osint.resolve_target")
    @patch("chimera_intel.core.physical_osint.find_physical_locations")
    def test_cli_locations_with_project(self, mock_find_locations, mock_resolve_target):
        """Tests the CLI command using an active project's context."""
        # Arrange

        mock_resolve_target.return_value = "ProjectCorp"
        mock_find_locations.return_value = PhysicalSecurityResult(
            query="ProjectCorp", locations_found=[]
        )

        # Act

        result = runner.invoke(physical_osint_app, ["locations"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_resolve_target.assert_called_with(
            None, required_assets=["company_name", "domain"]
        )
        mock_find_locations.assert_called_with("ProjectCorp")


if __name__ == "__main__":
    unittest.main()
