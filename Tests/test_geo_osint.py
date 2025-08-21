"""
Extended unit tests for the 'geo_osint' module.

This test suite provides comprehensive coverage for the geolocation data gathering,
map creation, and CLI command functionalities in 'chimera_intel.core.geo_osint.py'.
It uses 'unittest.mock' to simulate responses from the external IP-API.com service
and to mock the 'folium' library, ensuring that the tests are fast, reliable,
and do not depend on network access or file I/O.
"""

import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import Response, RequestError
from typer.testing import CliRunner

# Import the main app to test the CLI command

from chimera_intel.cli import app

# Import the functions and schemas to be tested

from chimera_intel.core.geo_osint import (
    get_geolocation_data,
    gather_geo_intel,
    create_ip_map,
)
from chimera_intel.core.schemas import GeoIntelData, GeoIntelResult

# Initialize the Typer test runner

runner = CliRunner()


# Use IsolatedAsyncioTestCase for testing async functions


class TestGeoOsint(unittest.IsolatedAsyncioTestCase):
    """Comprehensive test cases for the geo_osint module."""

    @patch("chimera_intel.core.geo_osint.async_client.get", new_callable=AsyncMock)
    async def test_get_geolocation_data_success(self, mock_get: AsyncMock):
        """Tests a successful geolocation lookup for a single IP address."""
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "query": "8.8.8.8",
            "country": "United States",
            "city": "Mountain View",
            "lat": 37.422,
            "lon": -122.084,
            "isp": "Google LLC",
            "org": "Google LLC",
        }
        mock_get.return_value = mock_response

        result = await get_geolocation_data("8.8.8.8")

        self.assertIsInstance(result, GeoIntelData)
        self.assertEqual(result.query, "8.8.8.8")
        self.assertEqual(result.country, "United States")
        self.assertEqual(result.isp, "Google LLC")

    @patch("chimera_intel.core.geo_osint.async_client.get", new_callable=AsyncMock)
    async def test_get_geolocation_data_api_failure(self, mock_get: AsyncMock):
        """Tests a failed geolocation lookup due to an API error message."""
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "fail",
            "message": "private range",
            "query": "192.168.1.1",
        }
        mock_get.return_value = mock_response

        result = await get_geolocation_data("192.168.1.1")
        self.assertIsNone(result)

    @patch("chimera_intel.core.geo_osint.async_client.get", new_callable=AsyncMock)
    async def test_get_geolocation_data_network_error(self, mock_get: AsyncMock):
        """Tests a failed geolocation lookup due to a network exception."""
        mock_get.side_effect = RequestError("Connection failed")
        result = await get_geolocation_data("1.1.1.1")
        self.assertIsNone(result)

    @patch("chimera_intel.core.geo_osint.get_geolocation_data", new_callable=AsyncMock)
    async def test_gather_geo_intel_logic(self, mock_get_geo_data: AsyncMock):
        """Tests the aggregation logic for multiple IP addresses."""
        # Simulate that one IP fails and two succeed

        mock_get_geo_data.side_effect = [
            GeoIntelData(query="8.8.8.8", country="United States"),
            None,  # Simulate a failed lookup for the second IP
            GeoIntelData(query="1.1.1.1", country="United States"),
        ]

        result = await gather_geo_intel(["8.8.8.8", "192.168.1.1", "1.1.1.1"])

        self.assertIsInstance(result, GeoIntelResult)
        self.assertEqual(len(result.locations), 2)
        self.assertEqual(result.locations[0].query, "8.8.8.8")
        # Ensure the mock was called for all three IPs

        self.assertEqual(mock_get_geo_data.call_count, 3)

    @patch("chimera_intel.core.geo_osint.folium.Map")
    @patch("chimera_intel.core.geo_osint.folium.Marker")
    def test_create_ip_map_success(self, mock_marker, mock_map):
        """Tests the successful creation of an HTML map."""
        mock_map_instance = mock_map.return_value
        geo_data = GeoIntelResult(
            locations=[
                GeoIntelData(
                    query="8.8.8.8",
                    lat=37.422,
                    lon=-122.084,
                    city="Mountain View",
                    country="USA",
                    isp="Google",
                ),
                GeoIntelData(
                    query="1.1.1.1",
                    lat=33.684,
                    lon=-117.826,
                    city="Irvine",
                    country="USA",
                    isp="Cloudflare",
                ),
            ]
        )
        create_ip_map(geo_data, "test_map.html")
        # Verify the map was created and centered

        mock_map.assert_called_once()
        # Verify two markers were added

        self.assertEqual(mock_marker.call_count, 2)
        # Verify the map was saved

        mock_map_instance.save.assert_called_with("test_map.html")

    @patch("chimera_intel.core.geo_osint.folium.Map")
    def test_create_ip_map_no_locations(self, mock_map):
        """Tests map creation when there is no data to plot."""
        geo_data = GeoIntelResult(locations=[])
        create_ip_map(geo_data, "no_data_map.html")
        # The map object should not even be created

        mock_map.assert_not_called()

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.geo_osint.asyncio.run")
    def test_cli_geo_osint_run_success(self, mock_asyncio_run: MagicMock):
        """Tests a successful run of the 'scan geo run' CLI command."""
        # Mock the return value of the main async function that `asyncio.run` will execute

        mock_asyncio_run.return_value = GeoIntelResult(
            locations=[GeoIntelData(query="8.8.8.8", country="USA")]
        )

        result = runner.invoke(app, ["scan", "geo", "run", "8.8.8.8"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn('"country": "USA"', result.stdout)

    @patch("chimera_intel.core.geo_osint.asyncio.run")
    @patch("chimera_intel.core.geo_osint.create_ip_map")
    def test_cli_geo_osint_with_map_option(
        self, mock_create_map: MagicMock, mock_asyncio_run: MagicMock
    ):
        """Tests the CLI command with the --map flag."""
        # The main async function returns a result

        mock_result = GeoIntelResult(locations=[])
        mock_asyncio_run.return_value = mock_result

        result = runner.invoke(
            app, ["scan", "geo", "run", "1.1.1.1", "--map", "map.html"]
        )

        self.assertEqual(result.exit_code, 0)
        # Verify that the map creation function was called with the correct arguments

        mock_create_map.assert_called_once_with(mock_result, "map.html")

    def test_cli_geo_osint_no_ips_provided(self):
        """Tests that the CLI command exits if no IP addresses are provided."""
        # Typer will handle this and show a "Missing argument" error

        result = runner.invoke(app, ["scan", "geo", "run"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Missing argument", result.stdout)


if __name__ == "__main__":
    unittest.main()
