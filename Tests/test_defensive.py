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
from httpx import RequestError
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

        This test mocks the central 'sync_client.get' method to simulate a 200 OK
        response from the HIBP API.

        Args:
            mock_get (MagicMock): A mock object replacing `sync_client.get`.
        """
        # Simulate a successful API response with complete breach data

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
        Tests the HIBP breach check for a case where no breaches are found.

        This test mocks the central 'sync_client.get' method to simulate a 404 Not Found
        response, which is the expected behavior from the HIBP API when a domain is clean.

        Args:
            mock_get (MagicMock): A mock object replacing `sync_client.get`.
        """
        # Simulate a 404 Not Found response

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = check_hibp_breaches("example.com", "fake_api_key")
        self.assertIsInstance(result, HIBPResult)
        self.assertEqual(result.breaches, [])
        self.assertIsNotNone(result.message)

    @patch("chimera_intel.core.defensive.subprocess.run")
    def test_find_typosquatting_dnstwist_success(self, mock_run: MagicMock):
        """
        Tests the dnstwist wrapper for a successful execution.

        This test mocks 'subprocess.run' to simulate a successful run of the
        dnstwist command-line tool, providing a sample JSON output.

        Args:
            mock_run (MagicMock): A mock object replacing `subprocess.run`.
        """
        # Simulate a successful subprocess run with complete JSON output

        mock_process = MagicMock()
        mock_process.stdout = '[{"fuzzer": "Original", "domain-name": "examp1e.com"}]'
        # Setting check=True in the function call will make this mock pass without an error

        mock_run.return_value = mock_process

        result = find_typosquatting_dnstwist("example.com")
        self.assertIsInstance(result, TyposquatResult)
        self.assertIsNotNone(result.results)
        self.assertEqual(len(result.results), 1)
        self.assertEqual(result.results[0].domain_name, "examp1e.com")

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_check_hibp_breaches_api_error(self, mock_get: MagicMock):
        """
        Tests the HIBP check during an API error.

        Args:
            mock_get (MagicMock): A mock object replacing `sync_client.get`.
        """
        # Simulate a more realistic network error

        mock_get.side_effect = RequestError("Network connection failed")

        result = check_hibp_breaches("example.com", "fake_api_key")
        self.assertIsInstance(result, HIBPResult)
        self.assertIsNotNone(result.error)
        self.assertIn("A network error occurred", result.error)

    @patch("chimera_intel.core.defensive.subprocess.run")
    def test_find_typosquatting_dnstwist_failure(self, mock_run: MagicMock):
        """
        Tests dnstwist when the command returns an error.

        Args:
            mock_run (MagicMock): A mock object replacing `subprocess.run`.
        """
        # Simulate that the process returns an error

        mock_run.side_effect = subprocess.CalledProcessError(
            1, "dnstwist", stderr="Some error"
        )

        result = find_typosquatting_dnstwist("example.com")
        self.assertIsInstance(result, TyposquatResult)
        self.assertIsNotNone(result.error)
        self.assertIn("returned an error", result.error)

    def test_search_github_leaks_no_api_key(self):
        """Tests the GitHub search without an API key."""
        result = search_github_leaks("query", "")
        self.assertIsInstance(result, GitHubLeaksResult)
        self.assertIsNotNone(result.error)
        self.assertIn("not found", result.error)


if __name__ == "__main__":
    unittest.main()
