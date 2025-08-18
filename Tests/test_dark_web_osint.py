import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import Response
from chimera_intel.core.dark_web_osint import search_dark_web


class TestDarkWebOsint(unittest.TestCase):
    """Test cases for the dark_web_osint module."""

    @patch("httpx.AsyncClient", new_callable=AsyncMock)
    def test_search_dark_web_success(self, mock_async_client):
        """Tests a successful dark web search."""
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.text = """
        <li class="result">
          <a>Test Title</a>
          <cite>http://test.onion</cite>
          <p>Test Description</p>
        </li>
        """
        # Configure the async context manager

        mock_client_instance = mock_async_client.return_value
        mock_client_instance.__aenter__.return_value.get.return_value = mock_response

        result = asyncio.run(search_dark_web("test query"))

        self.assertEqual(len(result.found_results), 1)
        self.assertEqual(result.found_results[0].title, "Test Title")
        self.assertIsNone(result.error)

    @patch("httpx.AsyncClient", new_callable=AsyncMock)
    def test_search_dark_web_timeout(self, mock_async_client):
        """Tests the dark web search when a timeout occurs."""
        mock_client_instance = mock_async_client.return_value
        mock_client_instance.__aenter__.return_value.get.side_effect = (
            asyncio.TimeoutError
        )

        result = asyncio.run(search_dark_web("test query"))

        self.assertEqual(len(result.found_results), 0)
        self.assertIsNotNone(result.error)
        self.assertIn("timed out", result.error)

    @patch("httpx.AsyncClient", new_callable=AsyncMock)
    def test_search_dark_web_generic_exception(self, mock_async_client):
        """Tests the dark web search when a generic exception occurs."""
        mock_client_instance = mock_async_client.return_value
        mock_client_instance.__aenter__.return_value.get.side_effect = Exception(
            "Proxy error"
        )

        result = asyncio.run(search_dark_web("test query"))

        self.assertEqual(len(result.found_results), 0)
        self.assertIsNotNone(result.error)
        self.assertIn("Is the Tor Browser running?", result.error)


if __name__ == "__main__":
    unittest.main()
