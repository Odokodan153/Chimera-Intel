import unittest
from unittest.mock import patch, MagicMock, AsyncMock

from chimera_intel.core.avint import get_live_flights
from chimera_intel.core.schemas import AVINTResult


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
                    "a8a2d6",
                    "SWR123  ",
                    "Switzerland",
                    1713217200,
                    1713217200,
                    8.5,
                    47.4,
                    1000.0,
                    False,
                    250.0,
                    45.0,
                    0.0,
                    None,
                    1100.0,
                    None,
                    False,
                    0,
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


if __name__ == "__main__":
    unittest.main()
