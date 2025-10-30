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
    get_subdomains_urlscan,
    get_subdomains_shodan,
    gather_footprint_data,
)

# --- CHANGE: Import the ThreatIntelResult model for mocking ---


from chimera_intel.core.schemas import ThreatIntelResult


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

        Args:
            mock_whois (MagicMock): A mock for the `whois.whois` function.
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

        Args:
            mock_whois (MagicMock): A mock for the `whois.whois` function.
        """
        mock_whois.return_value = None
        result = get_whois_info("nonexistentdomain123.com")
        self.assertIn("error", result)

    @patch("chimera_intel.core.footprint.whois.whois")
    def test_get_whois_info_exception(self, mock_whois):
        """
        Tests the WHOIS lookup when an unexpected exception occurs.

        Args:
            mock_whois (MagicMock): A mock for the `whois.whois` function.
        """
        mock_whois.side_effect = Exception("A generic network error")
        result = get_whois_info("google.com")
        self.assertIn("error", result)
        self.assertIn("A generic network error", result["error"])

    @patch("chimera_intel.core.footprint.dns.resolver.resolve")
    def test_get_dns_records_success(self, mock_resolve):
        """
        Tests a successful DNS resolution by mocking the 'dnspython' library call.

        Args:
            mock_resolve (MagicMock): A mock for `dns.resolver.resolve`.
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

        Args:
            mock_resolve (MagicMock): A mock for `dns.resolver.resolve`.
        """
        mock_resolve.side_effect = dns.resolver.NoAnswer
        result = get_dns_records("google.com")
        self.assertIn("A", result)
        self.assertIsNone(result["A"])

    @patch("chimera_intel.core.footprint.dns.resolver.resolve")
    def test_get_dns_records_nxdomain(self, mock_resolve):
        """
        Tests DNS resolution for a domain that does not exist.

        Args:
            mock_resolve (MagicMock): A mock for `dns.resolver.resolve`.
        """
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        result = get_dns_records("nonexistentdomain123.com")
        self.assertIn("error", result)
        self.assertIn("NXDOMAIN", result["error"])

    @patch("chimera_intel.core.http_client.async_client.get", new_callable=AsyncMock)
    def test_get_subdomains_virustotal_success(self, mock_async_get):
        """
        Tests a successful async call to the VirusTotal API.

        Args:
            mock_async_get (AsyncMock): A mock for `async_client.get`.
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

        Args:
            mock_async_get (AsyncMock): A mock for `async_client.get`.
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

        Args:
            mock_async_get (AsyncMock): A mock for `async_client.get`.
            mock_async_post (AsyncMock): A mock for `async_client.post`.
        """
        mock_get_response = MagicMock()
        mock_get_response.cookies = {"csrftoken": "fake_token"}
        mock_async_get.return_value = mock_get_response

        mock_post_response = MagicMock()
        mock_post_response.text = '<td class="col-md-4">sub1.example.com<br>'
        mock_async_post.return_value = mock_post_response

        result = asyncio.run(get_subdomains_dnsdumpster("example.com"))
        self.assertIn("sub1.example.com", result)

    # --- NEW ---
    @patch("chimera_intel.core.http_client.async_client.get", new_callable=AsyncMock)
    def test_get_subdomains_dnsdumpster_get_fail(self, mock_async_get):
        """
        Tests a failed scrape of DNSDumpster due to a network error on the GET request.

        Args:
            mock_async_get (AsyncMock): A mock for `async_client.get`.
        """
        mock_async_get.side_effect = RequestError("Network error")
        result = asyncio.run(get_subdomains_dnsdumpster("example.com"))
        self.assertEqual(result, [])

    # --- END NEW ---

    @patch("chimera_intel.core.http_client.async_client.get", new_callable=AsyncMock)
    def test_get_subdomains_threatminer_api_error(self, mock_async_get):
        """
        Tests the ThreatMiner call when the API returns an error status.

        Args:
            mock_async_get (AsyncMock): A mock for `async_client.get`.
        """
        mock_response = MagicMock()
        http_error = HTTPStatusError(
            "Error", request=MagicMock(), response=Response(status_code=500)
        )
        mock_response.raise_for_status.side_effect = http_error
        mock_async_get.return_value = mock_response

        result = asyncio.run(get_subdomains_threatminer("example.com"))
        self.assertEqual(result, [])

    @patch("chimera_intel.core.http_client.async_client.get", new_callable=AsyncMock)
    def test_get_subdomains_urlscan_success(self, mock_async_get):
        """
        Tests a successful async call to the URLScan.io API.

        Args:
            mock_async_get (AsyncMock): A mock for `async_client.get`.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {"page": {"domain": "sub1.example.com"}},
                {"page": {"domain": "sub2.example.com"}},
            ]
        }
        mock_async_get.return_value = mock_response
        result = asyncio.run(get_subdomains_urlscan("example.com"))
        self.assertIn("sub1.example.com", result)
        self.assertEqual(len(result), 2)

    @patch("chimera_intel.core.footprint.shodan.Shodan")
    def test_get_subdomains_shodan_success(self, mock_shodan_client):
        """
        Tests a successful async call to the Shodan API.

        Args:
            mock_shodan_client (MagicMock): A mock for `shodan.Shodan`.
        """
        mock_api = mock_shodan_client.return_value
        mock_api.search.return_value = {
            "matches": [
                {"hostnames": ["sub1.example.com"]},
                {"hostnames": ["sub2.example.com"]},
            ]
        }
        result = asyncio.run(get_subdomains_shodan("example.com", "fake_api_key"))
        self.assertIn("sub1.example.com", result)
        self.assertEqual(len(result), 2)

    @patch("chimera_intel.core.footprint.get_whois_info")
    @patch("chimera_intel.core.footprint.get_dns_records")
    @patch(
        "chimera_intel.core.footprint.get_subdomains_virustotal", new_callable=AsyncMock
    )
    @patch(
        "chimera_intel.core.footprint.get_subdomains_dnsdumpster",
        new_callable=AsyncMock,
    )
    @patch(
        "chimera_intel.core.footprint.get_subdomains_threatminer",
        new_callable=AsyncMock,
    )
    @patch(
        "chimera_intel.core.footprint.get_subdomains_urlscan", new_callable=AsyncMock
    )
    @patch("chimera_intel.core.footprint.get_subdomains_shodan", new_callable=AsyncMock)
    @patch("chimera_intel.core.footprint.get_threat_intel_otx", new_callable=AsyncMock)
    def test_gather_footprint_data_core_logic(
        self,
        mock_otx,
        mock_shodan,
        mock_urlscan,
        mock_threatminer,
        mock_dd,
        mock_vt,
        mock_dns,
        mock_whois,
    ):
        """
        Tests the main data aggregation and enrichment logic of gather_footprint_data.

        Args:
            mock_otx (AsyncMock): A mock for `get_threat_intel_otx`.
            mock_shodan (AsyncMock): A mock for `get_subdomains_shodan`.
            mock_urlscan (AsyncMock): A mock for `get_subdomains_urlscan`.
            mock_threatminer (AsyncMock): A mock for `get_subdomains_threatminer`.
            mock_dd (AsyncMock): A mock for `get_subdomains_dnsdumpster`.
            mock_vt (AsyncMock): A mock for `get_subdomains_virustotal`.
            mock_dns (MagicMock): A mock for `get_dns_records`.
            mock_whois (MagicMock): A mock for `get_whois_info`.
        """
        mock_whois.return_value = {"registrar": "Test Registrar"}
        mock_dns.return_value = {"A": ["1.1.1.1"]}
        mock_vt.return_value = ["vt.example.com"]
        mock_dd.return_value = ["dd.example.com", "vt.example.com"]
        mock_threatminer.return_value = []
        mock_urlscan.return_value = []
        mock_shodan.return_value = []

        mock_otx.return_value = ThreatIntelResult(
            indicator="1.1.1.1", is_malicious=True, pulse_count=5
        )

        with patch("chimera_intel.core.footprint.API_KEYS") as mock_keys:
            mock_keys.virustotal_api_key = "fake_key"
            mock_keys.shodan_api_key = None
            mock_keys.otx_api_key = "fake_otx_key"

            result = asyncio.run(gather_footprint_data("example.com"))

            self.assertEqual(result.domain, "example.com")
            self.assertEqual(result.footprint.whois_info["registrar"], "Test Registrar")
            self.assertEqual(result.footprint.subdomains.total_unique, 2)

            self.assertEqual(len(result.footprint.ip_threat_intelligence), 1)
            self.assertTrue(result.footprint.ip_threat_intelligence[0].is_malicious)
            self.assertEqual(result.footprint.ip_threat_intelligence[0].pulse_count, 5)

            for sub in result.footprint.subdomains.results:
                if sub.domain == "vt.example.com":
                    self.assertIn("HIGH", sub.confidence)

    @patch("chimera_intel.core.footprint.get_whois_info")
    @patch("chimera_intel.core.footprint.get_dns_records")
    @patch(
        "chimera_intel.core.footprint.get_subdomains_virustotal", new_callable=AsyncMock
    )
    @patch(
        "chimera_intel.core.footprint.get_subdomains_dnsdumpster",
        new_callable=AsyncMock,
    )
    @patch(
        "chimera_intel.core.footprint.get_subdomains_threatminer",
        new_callable=AsyncMock,
    )
    @patch(
        "chimera_intel.core.footprint.get_subdomains_urlscan", new_callable=AsyncMock
    )
    @patch("chimera_intel.core.footprint.get_subdomains_shodan", new_callable=AsyncMock)
    @patch("chimera_intel.core.footprint.get_threat_intel_otx", new_callable=AsyncMock)
    def test_gather_footprint_data_partial_failure(
        self,
        mock_otx,
        mock_shodan,
        mock_urlscan,
        mock_threatminer,
        mock_dd,
        mock_vt,
        mock_dns,
        mock_whois,
    ):
        """
        Tests that gather_footprint_data can handle failures from some of its sources.
        """
        # --- Arrange ---
        # Simulate some sources succeeding and others failing

        mock_whois.return_value = {"registrar": "Test Registrar"}
        mock_dns.return_value = {"A": ["1.1.1.1"]}
        mock_vt.return_value = ["vt.example.com"]  # VirusTotal succeeds
        # Correctly simulate a failure by returning an empty list, as per the function's error handling

        mock_dd.return_value = []  # DNSDumpster fails
        mock_threatminer.return_value = []
        mock_urlscan.return_value = []
        mock_shodan.return_value = []
        mock_otx.return_value = ThreatIntelResult(
            indicator="1.1.1.1", is_malicious=False
        )

        with patch("chimera_intel.core.footprint.API_KEYS") as mock_keys:
            mock_keys.virustotal_api_key = "fake_key"
            mock_keys.shodan_api_key = None
            mock_keys.otx_api_key = "fake_otx_key"

            # --- Act ---

            result = asyncio.run(gather_footprint_data("example.com"))

            # --- Assert ---
            # The function should still return a result, even with partial data.

            self.assertIsNotNone(result)
            self.assertEqual(result.domain, "example.com")
            # It should contain the data from the successful sources.

            self.assertEqual(result.footprint.whois_info["registrar"], "Test Registrar")
            self.assertEqual(result.footprint.subdomains.total_unique, 1)
            self.assertIn(
                "vt.example.com",
                [s.domain for s in result.footprint.subdomains.results],
            )
            # The failed source should not contribute any data.

            self.assertNotIn(
                "dd.example.com",
                [s.domain for s in result.footprint.subdomains.results],
            )


if __name__ == "__main__":
    unittest.main()
