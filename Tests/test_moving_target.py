import unittest
import json
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner
from chimera_intel.core.moving_target import moving_target_app
from chimera_intel.core.schemas import AVINTResult, FlightInfo

runner = CliRunner()


class TestMovingTarget(unittest.TestCase):
    """Test cases for the Moving Target (MOVINT) fusion module."""

    @patch("chimera_intel.core.moving_target.save_scan_to_db")
    @patch(
        "chimera_intel.core.moving_target.get_historical_geotags",
        new_callable=AsyncMock,
    )
    @patch(
        "chimera_intel.core.moving_target.get_vessel_position_once",
        new_callable=AsyncMock,
    )
    @patch("chimera_intel.core.moving_target.get_live_flights", new_callable=AsyncMock)
    @patch("chimera_intel.core.moving_target.API_KEYS")
    def test_cli_track_all_sources(
        self,
        mock_api_keys,
        mock_get_flights,
        mock_get_vessel,
        mock_get_geotags,
        mock_save_db,
    ):
        """Tests the 'track' command fusing all three sources."""
        # Arrange
        mock_api_keys.aisstream_api_key = "fake_key"

        # Mock AVINT
        mock_flight_info = FlightInfo(
            icao24="a1b2c3",
            callsign="TESTFLT",
            origin_country="USA",
            last_contact="2025-10-30T14:00:00Z",
            longitude=10.0,
            latitude=20.0,
            baro_altitude=10000,
            on_ground=False,
            velocity=250,
            true_track=180,
            vertical_rate=0,
            geo_altitude=10100,
            spi=False,
            position_source=0,
        )
        mock_get_flights.return_value = AVINTResult(
            total_flights=1, flights=[mock_flight_info]
        )

        # Mock MARINT (will be overwritten by AVINT as current location)
        mock_get_vessel.return_value = {
            "Latitude": 30.0,
            "Longitude": 40.0,
            "ImoNumber": 1234567,
            "Sog": 15,
            "Timestamp": "2025-10-30T13:00:00Z",
        }

        # Mock Social History
        mock_get_geotags.return_value = []

        # --- MODIFIED: Removed the explicit 'identifier' argument ---
        # Act
        result = runner.invoke(
            moving_target_app,
            [
                "track",
                "--icao24",
                "a1b2c3",
                "--imo",
                "1234567",
                "--username",
                "testuser",
            ],
        )
        # --- END MODIFICATION ---

        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        mock_get_flights.assert_called_with("a1b2c3")
        mock_get_vessel.assert_called_with("1234567", "fake_key")
        mock_get_geotags.assert_called_with("testuser")
        
        # --- MODIFIED: Check for the auto-generated identifier ---
        expected_identifier = "icao24=a1b2c3 AND imo=1234567 AND username=testuser"
        mock_save_db.assert_called_once()
        # Check that the DB save call used the correct identifier
        self.assertEqual(mock_save_db.call_args[1]["target"], expected_identifier)

        output_data = json.loads(result.stdout)
        self.assertEqual(output_data["target_identifier"], expected_identifier)
        # --- END MODIFICATION ---

        # Check that the AVINT data (the last one processed) is the current location
        self.assertEqual(output_data["current_location"]["source"], "avint")
        self.assertEqual(output_data["current_location"]["latitude"], 20.0)