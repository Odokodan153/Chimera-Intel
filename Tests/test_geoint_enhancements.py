# [NEW FILE: tests/test_geoint_enhancements.py]

import unittest
from unittest.mock import patch, MagicMock
import googlemaps
from chimera_intel.core.physical_osint import (
    get_building_footprints, 
    get_logistics_route
)
from chimera_intel.core.geoint import (
    monitor_physical_events, 
    find_aerial_vehicles
)
from chimera_intel.core.schemas import (
    BuildingFootprint, 
    PhysicalEvent, 
    AerialVehicleInfo
)
from chimera_intel.core.config_loader import API_KEYS

class TestGeoIntEnhancements(unittest.TestCase):

    @patch("chimera_intel.core.physical_osint.sync_client.post")
    def test_get_building_footprints_success(self, mock_post):
        # Mock Overpass API response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "elements": [
                {
                    "type": "way",
                    "id": 12345,
                    "tags": {"building": "yes"},
                    "geometry": [{"lat": 40.71, "lon": -74.00}]
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        footprints = get_building_footprints(40.71, -74.00, radius=100)
        self.assertEqual(len(footprints), 1)
        self.assertIsInstance(footprints[0], BuildingFootprint)
        self.assertEqual(footprints[0].osm_id, 12345)
        mock_post.assert_called_once()

    @patch.object(googlemaps.Client, "directions")
    def test_get_logistics_route_success(self, mock_directions):
        # Mock Google Maps Directions response
        mock_directions.return_value = [
            {
                "summary": "I-95 S",
                "legs": [{"distance": {"text": "100 mi"}, "duration": {"text": "2 hours"}}],
                "copyrights": "Google"
            }
        ]
        # Mock API_KEYS
        API_KEYS.google_maps_api_key = "fake_gmaps_key"

        route = get_logistics_route("New York, NY", "Philadelphia, PA")
        self.assertIsNotNone(route)
        self.assertEqual(route["summary"], "I-95 S")
        self.assertEqual(route["distance"], "100 mi")
        mock_directions.assert_called_once_with("New York, NY", "Philadelphia, PA", mode="driving")

    @patch("chimera_intel.core.geoint.sync_client.get")
    def test_monitor_physical_events_success(self, mock_get):
        # Mock NewsAPI response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "ok",
            "articles": [
                {
                    "title": "Protest at Tesla Gigafactory",
                    "source": {"name": "Tech News"},
                    "url": "example.com",
                    "publishedAt": "2025-11-01T12:00:00Z",
                    "description": "A protest occurred today."
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        API_KEYS.news_api_key = "fake_news_key"

        result = monitor_physical_events(query="Tesla", domain="example.com")
        self.assertEqual(len(result.events_found), 1)
        self.assertIsInstance(result.events_found[0], PhysicalEvent)
        self.assertEqual(result.events_found[0].title, "Protest at Tesla Gigafactory")
        mock_get.assert_called_once()

    @patch("chimera_intel.core.geoint.sync_client.get")
    def test_find_aerial_vehicles_success(self, mock_get):
        # Mock ADS-B Exchange response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "ac": [
                {
                    "hex": "a12345",
                    "flight": "DRONE01",
                    "lat": 37.0,
                    "lon": -76.0,
                    "alt_geom": 1500, # Low altitude
                    "gs": 50, # Slow speed
                    "t": "UAV"
                },
                {
                    "hex": "b67890",
                    "flight": "UAL123",
                    "lat": 37.1,
                    "lon": -76.1,
                    "alt_geom": 35000,
                    "gs": 450,
                    "t": "B737"
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        API_KEYS.adsbexchange_api_key = "fake_adsb_key"

        result = find_aerial_vehicles(lat=37.0, lon=-76.0, radius_km=50)
        self.assertEqual(result.total_vehicles, 1) # Only the UAV
        self.assertIsInstance(result.vehicles_found[0], AerialVehicleInfo)
        self.assertEqual(result.vehicles_found[0].hex, "a12345")
        self.assertEqual(result.vehicles_found[0].vehicle_type, "UAV")
        mock_get.assert_called_once()

if __name__ == "__main__":
    unittest.main()