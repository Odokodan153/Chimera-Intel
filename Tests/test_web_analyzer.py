import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

# Use the absolute import path for the package structure
from chimera_intel.core.web_analyzer import get_tech_stack_builtwith, get_tech_stack_wappalyzer, get_traffic_similarweb

class TestWebAnalyzer(unittest.TestCase):

    @patch('chimera_intel.core.web_analyzer.httpx.AsyncClient')
    def test_get_tech_stack_builtwith_success(self, mock_async_client):
        """Tests a successful async call to the BuiltWith API."""
        # --- Setup the mock for the async context manager ---
        mock_client_instance = mock_async_client.return_value.__aenter__.return_value
        
        # --- Simulate a successful API response ---
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "Results": [{
                "Result": {
                    "Paths": [{
                        "Technologies": [{"Name": "Nginx"}, {"Name": "React"}]
                    }]
                }
            }]
        }
        mock_client_instance.get = AsyncMock(return_value=mock_response)

        # --- Run the async function ---
        result = asyncio.run(get_tech_stack_builtwith("example.com", "fake_api_key", mock_client_instance))

        # --- Assert against the actual returned list ---
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        self.assertIn("Nginx", result)

    def test_get_tech_stack_builtwith_no_key(self):
        """Tests the defensive check for a missing API key without making a real call."""
        # This function is async, so we need to run it in an event loop
        # We can pass a dummy client as it should not be used when the key is None.
        dummy_client = None
        result = asyncio.run(get_tech_stack_builtwith("example.com", None, dummy_client))
        self.assertEqual(result, []) # It should return an empty list

    @patch('chimera_intel.core.web_analyzer.httpx.AsyncClient')
    def test_get_traffic_similarweb_success(self, mock_async_client):
        """Tests a successful async call to the Similarweb API."""
        mock_client_instance = mock_async_client.return_value.__aenter__.return_value
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"visits": "some_traffic_data"}
        mock_client_instance.get = AsyncMock(return_value=mock_response)

        result = asyncio.run(get_traffic_similarweb("example.com", "fake_api_key", mock_client_instance))

        self.assertIn("visits", result)

if __name__ == '__main__':
    unittest.main()