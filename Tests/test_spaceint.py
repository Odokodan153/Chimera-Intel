import unittest
from unittest.mock import patch, Mock
from src.chimera_intel.core.spaceint import SpaceInt


class TestSpaceInt(unittest.TestCase):
    def setUp(self):
        self.spaceint = SpaceInt()

    @patch("requests.get")
    def test_get_satellite_tle_success(self, mock_get):
        # Mock a successful API response

        mock_response = unittest.mock.Mock()
        mock_response.status_code = 200
        mock_response.text = "ISS (ZARYA)\n1 25544U 98067A   23276.50000000  .00001182  00000-0  29815-4 0  9993\n2 25544  51.6416 251.2916 0006771  45.5416  69.4678 15.494872238416"
        mock_get.return_value = mock_response

        tle = self.spaceint.get_satellite_tle(25544)
        self.assertIsNotNone(tle)
        self.assertEqual(len(tle), 3)
        self.assertEqual(tle[0], "ISS (ZARYA)")

    def test_get_satellite_position(self):
        # TLE for ISS

        line1 = "1 25544U 98067A   23276.50000000  .00001182  00000-0  29815-4 0  9993"
        line2 = "2 25544  51.6416 251.2916 0006771  45.5416  69.4678 15.494872238416"
        position = self.spaceint.get_satellite_position(line1, line2)
        self.assertIsNotNone(position)
        self.assertEqual(len(position), 3)

    @patch("requests.get")
    @patch("rich.console.Console.print")
    def test_predict_flyover(self, mock_print, mock_get):
        # Mock a successful API response for TLE data

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "ISS (ZARYA)\n1 25544U 98067A   23276.50000000  .00001182  00000-0  29815-4 0  9993\n2 25544  51.6416 251.2916 0006771  45.5416  69.4678 15.494872238416"
        mock_get.return_value = mock_response

        # Call the predict_flyover function

        self.spaceint.predict_flyover(
            25544, 42.6977, 23.3219
        )  # Sofia, Bulgaria coordinates

        # Assert that the print method was called, indicating the function ran

        self.assertTrue(mock_print.called)


if __name__ == "__main__":
    unittest.main()
