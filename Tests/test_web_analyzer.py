import unittest
from unittest.mock import patch, MagicMock
from chimera_intel.core.web_analyzer import get_tech_stack_builtwith, get_traffic_similarweb

class TestWebAnalyzer(unittest.TestCase):

    @patch('chimera_intel.core.web_analyzer.requests.get')
    def test_get_tech_stack_builtwith_success(self, mock_get):
        # Simulate a successful BuiltWith API call
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"Results": "some_data"}
        mock_get.return_value = mock_response
        result = get_tech_stack_builtwith("example.com", "fake_api_key")
        self.assertIn("Results", result)

    def test_get_tech_stack_builtwith_no_key(self):
        # Test the defensive check for a missing API key
        result = get_tech_stack_builtwith("example.com", None)
        self.assertIn("error", result)
        self.assertEqual(result["error"], "BuiltWith API key not found.")

    @patch('chimera_intel.core.web_analyzer.requests.get')
    def test_get_traffic_similarweb_success(self, mock_get):
        # Simulate a successful Similarweb API call
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"visits": "some_traffic_data"}
        mock_get.return_value = mock_response
        result = get_traffic_similarweb("example.com", "fake_api_key")
        self.assertIn("visits", result)

if __name__ == '__main__':
    unittest.main()