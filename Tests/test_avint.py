import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner

from chimera_intel.core.avint import get_live_flights, avint_app
from chimera_intel.core.schemas import AVINTResult

# Create a runner for CLI tests
runner = CliRunner()

class TestAvint(unittest.IsolatedAsyncioTestCase):
    """Test cases for the avint module."""

    @patch("chimera_intel.core.avint.async_client.get", new_callable=AsyncMock)
    async def test_get_live_flights_success(self, mock_get):
        """Tests a successful retrieval of live flight data."""
        # Arrange
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "time": 1713217200,
            "states": [
                [
                    "a8a2d6", "SWR123  ", "Switzerland", 1713217200, 1713217200,
                    8.5, 47.4, 1000.0, False, 250.0, 45.0, 0.0, None, 1100.0,
                    None, False, 0,
                ]
            ],
        }
        mock_get.return_value = mock_response

        # Act
        result = await get_live_flights()

        # Assert
        self.assertIsInstance(result, AVINTResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_flights, 1)
        self.assertEqual(result.flights[0].callsign, "SWR123")
        # Check that the default URL was called
        mock_get.assert_called_with("https://opensky-network.org/api/states/all")

    # --- Extended Test ---
    @patch("chimera_intel.core.avint.async_client.get", new_callable=AsyncMock)
    async def test_get_live_flights_with_icao24(self, mock_get):
        """Tests retrieval for a specific icao24."""
        # Arrange
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"time": 1713217200, "states": []}
        mock_get.return_value = mock_response

        # Act
        result = await get_live_flights(icao24="a8a2d6")

        # Assert
        self.assertIsNone(result.error)
        self.assertEqual(result.total_flights, 0)
        # Check that the URL with the icao24 parameter was called
        mock_get.assert_called_with("https://opensky-network.org/api/states/all?icao24=a8a2d6")

    # --- Extended Test ---
    @patch("chimera_intel.core.avint.async_client.get", new_callable=AsyncMock)
    async def test_get_live_flights_api_error(self, mock_get):
        """Tests the exception handling block for API failures."""
        # Arrange
        mock_get.side_effect = Exception("API connection failed")

        # Act
        result = await get_live_flights()

        # Assert
        self.assertIsInstance(result, AVINTResult)
        self.assertIsNotNone(result.error)
        self.assertIn("An API error occurred: API connection failed", result.error)
        self.assertEqual(result.total_flights, 0)

    # --- Extended Test: CLI Commands ---

    @patch("chimera_intel.core.avint.get_live_flights", new_callable=AsyncMock)
    def test_cli_track_success_all_flights(self, mock_get_live_flights):
        """Tests the 'track' CLI command without an icao24 filter."""
        # Arrange
        mock_flight = MagicMock(
            callsign="SWR123", origin_country="Switzerland", on_ground=False,
            velocity=250.0, baro_altitude=1000.0
        )
        mock_result = AVINTResult(total_flights=1, flights=[mock_flight], error=None)
        mock_get_live_flights.return_value = mock_result

        # Act
        result = runner.invoke(avint_app, ["track"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Found 1 live flights", result.stdout)
        self.assertIn("SWR123", result.stdout) # Check if table is printed
        mock_get_live_flights.assert_called_with(None)

    # --- Extended Test ---
    @patch("chimera_intel.core.avint.get_live_flights", new_callable=AsyncMock)
    def test_cli_track_success_specific_flight(self, mock_get_live_flights):
        """Tests the 'track' CLI command with an --icao24 filter."""
        # Arrange
        mock_get_live_flights.return_value = AVINTResult(total_flights=0, flights=[], error=None)

        # Act
        result = runner.invoke(avint_app, ["track", "--icao24", "a8a2d6"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Tracking aircraft with ICAO24: a8a2d6", result.stdout)
        mock_get_live_flights.assert_called_with("a8a2d6")

    # --- Extended Test ---
    @patch("chimera_intel.core.avint.get_live_flights", new_callable=AsyncMock)
    @patch("chimera_intel.core.avint.save_or_print_results")
    @patch("chimera_intel.core.avint.save_scan_to_db")
    def test_cli_track_with_output_file(
        self, mock_save_db, mock_save_print, mock_get_live_flights
    ):
        """Tests the 'track' CLI command with an --output file."""
        # Arrange
        mock_dump_dict = {"total_flights": 0, "flights": []}
        mock_result = MagicMock(
            error=None,
            total_flights=0,
            model_dump=lambda exclude_none: mock_dump_dict
        )
        mock_get_live_flights.return_value = mock_result

        # Act
        result = runner.invoke(avint_app, ["track", "--output", "flights.json"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        # Check that the results were saved, not printed as a table
        mock_save_print.assert_called_with(mock_dump_dict, "flights.json")
        mock_save_db.assert_called_with(
            target="live_flights",
            module="avint_live_tracking",
            data=mock_dump_dict
        )
        self.assertNotIn("Live Flight Information", result.stdout) # No table

    # --- Extended Test ---
    @patch("chimera_intel.core.avint.get_live_flights", new_callable=AsyncMock)
    def test_cli_track_api_error(self, mock_get_live_flights):
        """Tests the 'track' CLI command when the API returns an error."""
        # Arrange
        mock_result = AVINTResult(total_flights=0, flights=[], error="API is down")
        mock_get_live_flights.return_value = mock_result

        # Act
        result = runner.invoke(avint_app, ["track"])

        # Assert
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Error:", result.stdout)
        self.assertIn("API is down", result.stdout)


if __name__ == "__main__":
    unittest.main()