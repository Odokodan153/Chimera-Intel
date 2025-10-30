import unittest
from unittest.mock import patch, Mock
import requests
from typer.testing import CliRunner

from src.chimera_intel.core.spaceint import SpaceInt, app

# Mock TLE data for reuse
MOCK_TLE_NAME = "ISS (ZARYA)"
MOCK_TLE_LINE1 = "1 25544U 98067A   23276.50000000  .00001182  00000-0  29815-4 0  9993"
MOCK_TLE_LINE2 = "2 25544  51.6416 251.2916 0006771  45.5416  69.4678 15.494872238416"
MOCK_TLE_TEXT = f"{MOCK_TLE_NAME}\n{MOCK_TLE_LINE1}\n{MOCK_TLE_LINE2}"


class TestSpaceInt(unittest.TestCase):
    def setUp(self):
        self.spaceint = SpaceInt()
        self.runner = CliRunner()

    # --- Tests for SpaceInt Class ---

    @patch("requests.get")
    def test_get_satellite_tle_success(self, mock_get):
        # Mock a successful API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = MOCK_TLE_TEXT
        mock_get.return_value = mock_response

        tle = self.spaceint.get_satellite_tle(25544)
        self.assertIsNotNone(tle)
        self.assertEqual(len(tle), 3)
        self.assertEqual(tle[0], MOCK_TLE_NAME)
        self.assertEqual(tle[1], MOCK_TLE_LINE1)
        self.assertEqual(tle[2], MOCK_TLE_LINE2)

    @patch("requests.get")
    @patch("src.chimera_intel.core.spaceint.console.print")
    def test_get_satellite_tle_request_exception(self, mock_print, mock_get):
        # Mock a request exception
        mock_get.side_effect = requests.exceptions.RequestException("API Error")

        tle = self.spaceint.get_satellite_tle(25544)
        self.assertIsNone(tle)
        mock_print.assert_called_with("[bold red]Error fetching TLE data: API Error[/bold red]")

    @patch("requests.get")
    def test_get_satellite_tle_invalid_data(self, mock_get):
        # Mock an API response with incomplete data
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "INCOMPLETE DATA\n1 25544U 98067A"
        mock_get.return_value = mock_response

        tle = self.spaceint.get_satellite_tle(25544)
        self.assertIsNone(tle)

    def test_get_satellite_position_success(self):
        # Test position calculation with valid TLE
        position = self.spaceint.get_satellite_position(MOCK_TLE_LINE1, MOCK_TLE_LINE2)
        self.assertIsNotNone(position)
        self.assertEqual(len(position), 3)

    @patch("src.chimera_intel.core.spaceint.Satrec.twoline2rv")
    @patch("src.chimera_intel.core.spaceint.console.print")
    def test_get_satellite_position_exception(self, mock_print, mock_twoline2rv):
        # Mock an exception during satellite position calculation
        mock_twoline2rv.side_effect = Exception("SGP4 Error")
        
        position = self.spaceint.get_satellite_position(MOCK_TLE_LINE1, MOCK_TLE_LINE2)
        self.assertIsNone(position)
        mock_print.assert_called_with("[bold red]Error calculating satellite position: SGP4 Error[/bold red]")

    @patch("src.chimera_intel.core.spaceint.Satrec.sgp4")
    def test_get_satellite_position_sgp4_error(self, mock_sgp4):
        # Mock an SGP4 propagation error (e != 0)
        mock_sgp4.return_value = (1, None, None)  # e = 1 indicates an error

        position = self.spaceint.get_satellite_position(MOCK_TLE_LINE1, MOCK_TLE_LINE2)
        self.assertIsNone(position)

    @patch("src.chimera_intel.core.spaceint.SpaceInt.get_satellite_tle")
    def test_predict_flyover_no_tle(self, mock_get_tle):
        # Mock TLE fetch returning None
        mock_get_tle.return_value = None

        # Call the predict_flyover function
        result = self.spaceint.predict_flyover(25544, 42.6977, 23.3219)
        
        # Function should return early
        self.assertIsNone(result)

    # --- Tests for Typer CLI Commands ---

    @patch("src.chimera_intel.core.spaceint.SpaceInt.get_satellite_position")
    @patch("src.chimera_intel.core.spaceint.SpaceInt.get_satellite_tle")
    def test_track_command_success(self, mock_get_tle, mock_get_position):
        # Mock successful TLE and position data
        mock_get_tle.return_value = (MOCK_TLE_NAME, MOCK_TLE_LINE1, MOCK_TLE_LINE2)
        mock_get_position.return_value = (1000.0, 2000.0, 3000.0)

        result = self.runner.invoke(app, ["track", "25544"])
        
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Successfully fetched TLE for: ISS (ZARYA)", result.stdout)
        self.assertIn("Current Position of ISS (ZARYA)", result.stdout)
        self.assertIn("X", result.stdout)
        self.assertIn("1000.00", result.stdout)
        self.assertIn("Y", result.stdout)
        self.assertIn("2000.00", result.stdout)
        self.assertIn("Z", result.stdout)
        self.assertIn("3000.00", result.stdout)

    @patch("src.chimera_intel.core.spaceint.SpaceInt.get_satellite_tle")
    def test_track_command_tle_fail(self, mock_get_tle):
        # Mock TLE fetch failure
        mock_get_tle.return_value = None

        result = self.runner.invoke(app, ["track", "25544"])
        
        self.assertEqual(result.exit_code, 0)
        # No error message is printed from the command itself, only from get_satellite_tle (which is mocked)
        self.assertNotIn("Successfully fetched TLE", result.stdout)
        self.assertNotIn("Could not calculate satellite position", result.stdout)

    @patch("src.chimera_intel.core.spaceint.SpaceInt.get_satellite_position")
    @patch("src.chimera_intel.core.spaceint.SpaceInt.get_satellite_tle")
    def test_track_command_position_fail(self, mock_get_tle, mock_get_position):
        # Mock successful TLE but failed position calculation
        mock_get_tle.return_value = (MOCK_TLE_NAME, MOCK_TLE_LINE1, MOCK_TLE_LINE2)
        mock_get_position.return_value = None

        result = self.runner.invoke(app, ["track", "25544"])
        
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Successfully fetched TLE for: ISS (ZARYA)", result.stdout)
        self.assertIn("Could not calculate satellite position.", result.stdout)

    @patch("requests.get")
    def test_launches_command_success(self, mock_get):
        # Mock successful launch API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {
                    "net": "2025-12-01T12:00:00Z",
                    "rocket": {"configuration": {"full_name": "Falcon 9"}},
                    "mission": {"name": "Starlink Group 10-1"},
                    "pad": {"name": "SLC-40"}
                }
            ]
        }
        mock_get.return_value = mock_response

        result = self.runner.invoke(app, ["launches", "--limit", "1"])
        
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Upcoming Rocket Launches", result.stdout)
        self.assertIn("Falcon 9", result.stdout)
        self.assertIn("Starlink Group 10-1", result.stdout)
        self.assertIn("SLC-40", result.stdout)

    @patch("requests.get")
    def test_launches_command_api_fail(self, mock_get):
        # Mock launch API request exception
        mock_get.side_effect = requests.exceptions.RequestException("Launch API Error")

        result = self.runner.invoke(app, ["launches", "--limit", "1"])
        
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Error fetching launch data: Launch API Error", result.stdout)

    @patch("src.chimera_intel.core.spaceint.SpaceInt.predict_flyover")
    def test_predict_command_success(self, mock_predict_flyover):
        # Test that the 'predict' command calls the class method
        result = self.runner.invoke(app, ["predict", "25544", "--lat", "42.7", "--lon", "23.3"])
        
        self.assertEqual(result.exit_code, 0)
        mock_predict_flyover.assert_called_with(25544, 42.7, 23.3, 24)

    @patch("src.chimera_intel.core.spaceint.SpaceInt.predict_flyover")
    def test_predict_command_with_hours(self, mock_predict_flyover):
        # Test that 'predict' command passes 'hours' argument
        result = self.runner.invoke(app, ["predict", "25544", "--lat", "42.7", "--lon", "23.3", "--hours", "48"])
        
        self.assertEqual(result.exit_code, 0)
        mock_predict_flyover.assert_called_with(25544, 42.7, 23.3, 48)


if __name__ == "__main__":
    unittest.main()