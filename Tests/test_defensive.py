"""
Unit tests for the 'defensive' module.

This test suite verifies the functionality of the defensive scanning functions
in 'chimera_intel.core.defensive.py'. It uses 'unittest.mock' to simulate
responses from external APIs and command-line tools, ensuring that the tests
are reliable and do not depend on network access.
"""

import unittest
from unittest.mock import patch, MagicMock
import subprocess
from httpx import RequestError, HTTPStatusError, Response
from chimera_intel.core.defensive import (
    check_hibp_breaches,
    find_typosquatting_dnstwist,
    search_github_leaks,
)
from chimera_intel.core.schemas import HIBPResult, TyposquatResult, GitHubLeaksResult


class TestDefensive(unittest.TestCase):
    """Test cases for defensive scanning functions."""

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_check_hibp_breaches_found(self, mock_get: MagicMock):
        """
        Tests the HIBP breach check for a successful case where breaches are found.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "Name": "Breach1",
                "Title": "Test Breach",
                "Domain": "example.com",
                "BreachDate": "2025-01-01",
                "PwnCount": 12345,
                "Description": "A test breach description.",
                "DataClasses": ["Email addresses", "Passwords"],
                "IsVerified": True,
            }
        ]
        mock_get.return_value = mock_response

        result = check_hibp_breaches("example.com", "fake_api_key")
        self.assertIsInstance(result, HIBPResult)
        self.assertIsNotNone(result.breaches)
        self.assertEqual(len(result.breaches), 1)
        self.assertEqual(result.breaches[0].Name, "Breach1")

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_check_hibp_breaches_not_found(self, mock_get: MagicMock):
        """
        Tests the HIBP breach check for a case where no breaches are found (404).
        """
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = check_hibp_breaches("example.com", "fake_api_key")
        self.assertIsInstance(result, HIBPResult)
        self.assertEqual(result.breaches, [])
        self.assertIn("No breaches found", result.message)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_check_hibp_breaches_http_error(self, mock_get: MagicMock):
        """
        Tests the HIBP check when an HTTP error (e.g., 500) occurs.
        """
        mock_response = MagicMock()
        mock_response.status_code = 500
        # Mocking a response object for raise_for_status

        http_error = HTTPStatusError(
            "Server Error", request=MagicMock(), response=Response(status_code=500)
        )
        mock_response.raise_for_status.side_effect = http_error
        mock_get.return_value = mock_response

        result = check_hibp_breaches("example.com", "fake_api_key")
        self.assertIsInstance(result, HIBPResult)
        self.assertIsNotNone(result.error)
        self.assertIn("500", result.error)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_check_hibp_breaches_network_error(self, mock_get: MagicMock):
        """
        Tests the HIBP check during a network error.
        """
        mock_get.side_effect = RequestError("Network connection failed")
        result = check_hibp_breaches("example.com", "fake_api_key")
        self.assertIsInstance(result, HIBPResult)
        self.assertIsNotNone(result.error)
        self.assertIn("network error", result.error)

    def test_check_hibp_breaches_no_api_key(self):
        """Tests the HIBP check when the API key is missing."""
        result = check_hibp_breaches("example.com", "")
        self.assertIsInstance(result, HIBPResult)
        self.assertIsNotNone(result.error)
        self.assertIn("API key not found", result.error)

    @patch("chimera_intel.core.defensive.subprocess.run")
    def test_find_typosquatting_dnstwist_success(self, mock_run: MagicMock):
        """
        Tests the dnstwist wrapper for a successful execution.
        """
        mock_process = MagicMock()
        mock_process.stdout = '[{"fuzzer": "Original", "domain-name": "examp1e.com"}]'
        mock_run.return_value = mock_process

        result = find_typosquatting_dnstwist("example.com")
        self.assertIsInstance(result, TyposquatResult)
        self.assertIsNotNone(result.results)
        self.assertEqual(len(result.results), 1)

    @patch("chimera_intel.core.defensive.subprocess.run")
    def test_find_typosquatting_dnstwist_command_not_found(self, mock_run: MagicMock):
        """
        Tests dnstwist when the command is not found in the system.
        """
        mock_run.side_effect = FileNotFoundError
        result = find_typosquatting_dnstwist("example.com")
        self.assertIsInstance(result, TyposquatResult)
        self.assertIsNotNone(result.error)
        self.assertIn("command not found", result.error)

    @patch("chimera_intel.core.defensive.subprocess.run")
    def test_find_typosquatting_dnstwist_called_process_error(
        self, mock_run: MagicMock
    ):
        """
        Tests dnstwist when the command returns a non-zero exit code.
        """
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "dnstwist", stderr="Some error"
        )
        result = find_typosquatting_dnstwist("example.com")
        self.assertIsInstance(result, TyposquatResult)
        self.assertIsNotNone(result.error)
        self.assertIn("returned an error", result.error)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_search_github_leaks_success(self, mock_get: MagicMock):
        """
        Tests a successful GitHub leak search.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "total_count": 1,
            "items": [{"url": "http://leak.com"}],
        }
        mock_get.return_value = mock_response

        result = search_github_leaks("example.com api_key", "fake_pat")
        self.assertIsInstance(result, GitHubLeaksResult)
        self.assertEqual(result.total_count, 1)
        self.assertIsNotNone(result.items)
        self.assertEqual(len(result.items), 1)

    def test_search_github_leaks_no_api_key(self):
        """Tests the GitHub search without an API key."""
        result = search_github_leaks("query", "")
        self.assertIsInstance(result, GitHubLeaksResult)
        self.assertIsNotNone(result.error)
        self.assertIn("not found", result.error)


if __name__ == "__main__":
    unittest.main()
