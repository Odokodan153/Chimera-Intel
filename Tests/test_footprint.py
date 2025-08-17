"""
Unit tests for the 'footprint' module.

This test suite verifies the functionality of the data gathering and utility functions
in 'chimera_intel.core.footprint.py'. It uses the 'unittest.mock' library
to isolate functions from the network and ensure tests are fast and deterministic.
"""

import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import dns.resolver
from httpx import RequestError, HTTPStatusError, Response

# Use the absolute import path for the package structure

from chimera_intel.core.utils import is_valid_domain
from chimera_intel.core.footprint import (
    get_whois_info,
    get_dns_records,
    get_subdomains_virustotal,
    get_subdomains_dnsdumpster,
    get_subdomains_threatminer,
)


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

    @patch("chimera_intel.core.footprint.whois.whois")
    def test_get_whois_info_success(self, mock_whois):
        """
        Tests a successful WHOIS lookup by mocking the 'whois' library call.
        """
        mock_whois.return_value = {
            "domain_name": ["google.com", "GOOGLE.COM"],
            "registrar": "MarkMonitor Inc.",
        }
        result = get_whois_info("google.com")
        self.assertEqual(result.get("registrar"), "MarkMonitor Inc.")

    @patch("chimera_intel.core.footprint.whois.whois")
    def test_get_whois_info_failure(self, mock_whois):
        """
        Tests a failed WHOIS lookup where the domain is not found.
        """
        mock_whois.return_value = None
        result = get_whois_info("nonexistentdomain123.com")
        self.assertIn("error", result)

    @patch("chimera_intel.core.footprint.whois.whois")
    def test_get_whois_info_exception(self, mock_whois):
        """
        Tests the WHOIS lookup when an unexpected exception occurs.
        """
        mock_whois.side_effect = Exception("A generic network error")
        result = get_whois_info("google.com")
        self.assertIn("error", result)
        self.assertIn("A generic network error", result["error"])

    @patch("chimera_intel.core.footprint.dns.resolver.resolve")
    def test_get_dns_records_success(self, mock_resolve):
        """
        Tests a successful DNS resolution by mocking the 'dnspython' library call.
        """
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "1.2.3.4"
        mock_resolve.return_value = [mock_answer]
        result = get_dns_records("google.com")
        self.assertIn("A", result)
        self.assertEqual(result["A"][0], "1.2.3.4")

    @patch("chimera_intel.core.footprint.dns.resolver.resolve")
    def test_get_dns_records_no_answer(self, mock_resolve):
        """
        Tests DNS resolution when a specific record type has no answer.
        """
        mock_resolve.side_effect = dns.resolver.NoAnswer
        result = get_dns_records("google.com")
        # The key for 'A' record should exist, but its value should be None

        self.assertIn("A", result)
        self.assertIsNone(result["A"])

    @patch("chimera_intel.core.footprint.dns.resolver.resolve")
    def test_get_dns_records_nxdomain(self, mock_resolve):
        """
        Tests DNS resolution for a domain that does not exist.
        """
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        result = get_dns_records("nonexistentdomain123.com")
        self.assertIn("error", result)
        self.assertIn("NXDOMAIN", result["error"])

    @patch("chimera_intel.core.http_client.async_client.get", new_callable=AsyncMock)
    def test_get_subdomains_virustotal_success(self, mock_async_get):
        """
        Tests a successful async call to the VirusTotal API.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"id": "sub1.google.com"}, {"id": "sub2.google.com"}]
        }
        mock_async_get.return_value = mock_response

        result = asyncio.run(get_subdomains_virustotal("google.com", "fake_api_key"))

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        self.assertIn("sub1.google.com", result)

    @patch("chimera_intel.core.http_client.async_client.get", new_callable=AsyncMock)
    def test_get_subdomains_virustotal_api_error(self, mock_async_get):
        """
        Tests the VirusTotal call when the API returns an error.
        """
        mock_async_get.side_effect = RequestError("Network error")
        result = asyncio.run(get_subdomains_virustotal("google.com", "fake_api_key"))
        self.assertEqual(result, [])

    def test_get_subdomains_virustotal_no_api_key(self):
        """
        Tests the VirusTotal call when no API key is provided.
        """
        result = asyncio.run(get_subdomains_virustotal("google.com", ""))
        self.assertEqual(result, [])

    @patch("chimera_intel.core.http_client.async_client.post", new_callable=AsyncMock)
    @patch("chimera_intel.core.http_client.async_client.get", new_callable=AsyncMock)
    def test_get_subdomains_dnsdumpster_success(self, mock_async_get, mock_async_post):
        """
        Tests a successful async scrape of DNSDumpster.
        """
        # Mock GET to get CSRF token

        mock_get_response = MagicMock()
        mock_get_response.cookies = {"csrftoken": "fake_token"}
        mock_async_get.return_value = mock_get_response

        # Mock POST with results

        mock_post_response = MagicMock()
        mock_post_response.text = '<td class="col-md-4">sub1.example.com<br>'
        mock_async_post.return_value = mock_post_response

        result = asyncio.run(get_subdomains_dnsdumpster("example.com"))
        self.assertIn("sub1.example.com", result)

    @patch("chimera_intel.core.http_client.async_client.get", new_callable=AsyncMock)
    def test_get_subdomains_threatminer_api_error(self, mock_async_get):
        """
        Tests the ThreatMiner call when the API returns an error status.
        """
        mock_response = MagicMock()
        # Mocking a response object that can be used with raise_for_status

        http_error = HTTPStatusError(
            "Error", request=MagicMock(), response=Response(status_code=500)
        )
        mock_response.raise_for_status.side_effect = http_error
        mock_async_get.return_value = mock_response

        result = asyncio.run(get_subdomains_threatminer("example.com"))
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
