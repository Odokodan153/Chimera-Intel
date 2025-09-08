import unittest
from unittest.mock import patch

from chimera_intel.core.physical_osint import find_physical_locations
from chimera_intel.core.schemas import PhysicalSecurityResult


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


if __name__ == "__main__":
    unittest.main()
