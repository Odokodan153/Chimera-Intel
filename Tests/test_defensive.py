"""
Unit tests for the 'defensive' module.

This test suite verifies the functionality of the defensive scanning functions
in 'chimera_intel.core.defensive.py'. It uses 'unittest.mock' to simulate
responses from external APIs and command-line tools, ensuring that the tests
are reliable and do not depend on network access.
"""

import unittest
from unittest.mock import patch, MagicMock
from chimera_intel.core.defensive import (
    check_hibp_breaches,
    find_typosquatting_dnstwist,
)


class TestDefensive(unittest.TestCase):
    """Test cases for defensive scanning functions."""

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_check_hibp_breaches_found(self, mock_get):
        """
        Tests the HIBP breach check for a successful case where breaches are found.

        This test mocks the central 'sync_client.get' method to simulate a 200 OK
        response from the HIBP API.
        """
        # Simulate a successful API response with breach data

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"Name": "Breach1"}]
        mock_get.return_value = mock_response

        result = check_hibp_breaches("example.com", "fake_api_key")
        self.assertEqual(len(result.breaches), 1)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_check_hibp_breaches_not_found(self, mock_get):
        """
        Tests the HIBP breach check for a case where no breaches are found.

        This test mocks the central 'sync_client.get' method to simulate a 404 Not Found
        response, which is the expected behavior from the HIBP API when a domain is clean.
        """
        # Simulate a 404 Not Found response

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = check_hibp_breaches("example.com", "fake_api_key")
        self.assertEqual(len(result.breaches), 0)
        self.assertIsNotNone(result.message)

    @patch("chimera_intel.core.defensive.subprocess.run")
    def test_find_typosquatting_dnstwist_success(self, mock_run):
        """
        Tests the dnstwist wrapper for a successful execution.

        This test mocks 'subprocess.run' to simulate a successful run of the
        dnstwist command-line tool, providing a sample JSON output.
        """
        # Simulate a successful subprocess run with JSON output

        mock_process = MagicMock()
        mock_process.stdout = '[{"domain-name": "examp1e.com"}]'
        mock_run.return_value = mock_process

        result = find_typosquatting_dnstwist("example.com")
        self.assertEqual(result.results[0]["domain-name"], "examp1e.com")


if __name__ == "__main__":
    unittest.main()
