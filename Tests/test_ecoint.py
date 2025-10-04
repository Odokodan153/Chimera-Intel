# Tests/test_ecoint.py

import unittest
from unittest.mock import patch, Mock
from src.chimera_intel.core.ecoint import EcoInt


class TestEcoInt(unittest.TestCase):
    def setUp(self):
        self.ecoint = EcoInt()

    @patch("requests.get")
    def test_get_epa_violations_success(self, mock_get):
        # Mock a successful API response from the EPA

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "Results": {
                "Facilities": [
                    {
                        "CWPName": "Test Facility 1",
                        "CWPStreet": "123 Test St",
                        "CWPCity": "Testville",
                        "CWPState": "TS",
                        "LastInspectDate": "2023-10-26",
                        "CWPFormalCount": 2,
                        "CWPPenaltyCount": 5000,
                    }
                ]
            }
        }
        mock_get.return_value = mock_response

        violations = self.ecoint.get_epa_violations("TestCorp")
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["facility_name"], "Test Facility 1")

    @patch("requests.get")
    def test_get_ghg_emissions_success(self, mock_get):
        # Mock a successful API response from Climate TRACE

        self.ecoint.climatetrace_api_key = "fake_key"  # Set a dummy key for the test
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "assets": [
                {
                    "name": "Test Power Plant",
                    "country": "USA",
                    "sector": "Power",
                    "emissions": [
                        {"year": 2022, "emissions_quantity": 150000},
                        {"year": 2023, "emissions_quantity": 160000},
                    ],
                }
            ]
        }
        mock_get.return_value = mock_response

        emissions = self.ecoint.get_ghg_emissions("TestCorp")
        self.assertEqual(len(emissions), 1)
        self.assertEqual(emissions[0]["asset_name"], "Test Power Plant")
        self.assertEqual(emissions[0]["co2e_tonnes"], 160000)


if __name__ == "__main__":
    unittest.main()