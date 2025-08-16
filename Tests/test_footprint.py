"""
Unit tests for the 'footprint' module.

This test suite verifies the functionality of the data gathering and utility functions
in 'chimera_intel.core.footprint.py'. It uses the 'unittest.mock' library
to isolate functions from the network and ensure tests are fast and deterministic.
"""

import unittest
from unittest.mock import patch, MagicMock
import asyncio

# Use the absolute import path for the package structure
from chimera_intel.core.footprint import is_valid_domain, get_whois_info, get_dns_records, get_subdomains_virustotal

class TestFootprint(unittest.TestCase):
    """Test cases for footprint gathering functions."""

    def test_is_valid_domain(self):
        """
        Tests the domain validation regex for both valid and invalid cases.
        """
        self.assertTrue(is_valid_domain("google.com"))
        self.assertTrue(is_valid_domain("sub.domain.co.uk"))
        self.assertFalse(is_valid_domain("invalid-domain"))
        self.assertFalse(is_valid_domain("google.c"))
        self.assertFalse(is_valid_domain("-google.com"))

    @patch('chimera_intel.core.footprint.whois.whois')
    def test_get_whois_info_success(self, mock_whois):
        """
        Tests a successful WHOIS lookup by mocking the 'whois' library call.
        """
        # Simulate a successful WHOIS lookup with a valid response object
        mock_whois.return_value = MagicMock(domain_name="google.com", registrar="MarkMonitor Inc.")
        result = get_whois_info("google.com")
        self.assertEqual(result.get('registrar'), "MarkMonitor Inc.")

    @patch('chimera_intel.core.footprint.whois.whois')
    def test_get_whois_info_failure(self, mock_whois):
        """
        Tests a failed WHOIS lookup where the domain is not found.
        """
        # Simulate a failed WHOIS lookup where the response object has no domain_name
        mock_whois.return_value = MagicMock(domain_name=None)
        result = get_whois_info("nonexistentdomain123.com")
        self.assertIn("error", result)

    @patch('chimera_intel.core.footprint.dns.resolver.resolve')
    def test_get_dns_records_success(self, mock_resolve):
        """
        Tests a successful DNS resolution by mocking the 'dnspython' library call.
        """
        # Simulate a successful DNS resolution for an 'A' record
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "1.2.3.4"
        mock_resolve.return_value = [mock_answer]
        result = get_dns_records("google.com")
        self.assertIn("A", result)
        self.assertEqual(result["A"][0], "1.2.3.4")

    @patch('chimera_intel.core.footprint.async_client.get')
    def test_get_subdomains_virustotal_success(self, mock_async_get):
        """
        Tests a successful async call to the VirusTotal API.

        This test mocks the 'async_client.get' method to simulate a successful
        API response without making a real network request.
        """
        # --- Simulate a successful API response ---
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock() # Mock the check for HTTP errors
        mock_response.json.return_value = {
            "data": [{"id": "sub1.google.com"}, {"id": "sub2.google.com"}]
        }
        
        # Configure the mock 'get' method to be an async function that returns our simulated response.
        async def async_magic():
            return mock_response
        
        mock_async_get.return_value = async_magic()

        # --- Run the async function ---
        result = asyncio.run(get_subdomains_virustotal("google.com", "fake_api_key"))

        # --- Assert against the actual returned list ---
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        self.assertIn("sub1.google.com", result)

if __name__ == '__main__':
    unittest.main()