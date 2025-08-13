import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

# Use the absolute import path for the package structure
from chimera_intel.core.footprint import is_valid_domain, get_whois_info, get_dns_records, get_subdomains_virustotal

class TestFootprint(unittest.TestCase):

    def test_is_valid_domain(self):
        """Tests the domain validation regex for valid and invalid cases."""
        self.assertTrue(is_valid_domain("google.com"))
        self.assertTrue(is_valid_domain("sub.domain.co.uk"))
        self.assertFalse(is_valid_domain("invalid-domain"))
        self.assertFalse(is_valid_domain("google.c"))
        self.assertFalse(is_valid_domain("-google.com"))

    @patch('chimera_intel.core.footprint.whois.whois')
    def test_get_whois_info_success(self, mock_whois):
        """Tests a successful WHOIS lookup by mocking the whois library."""
        # Simulate a successful WHOIS lookup with a valid response object
        mock_whois.return_value = MagicMock(domain_name="google.com", registrar="MarkMonitor Inc.")
        result = get_whois_info("google.com")
        self.assertEqual(result.get('registrar'), "MarkMonitor Inc.")

    @patch('chimera_intel.core.footprint.whois.whois')
    def test_get_whois_info_failure(self, mock_whois):
        """Tests a failed WHOIS lookup where the domain is not found."""
        # Simulate a failed WHOIS lookup where the response object has no domain_name
        mock_whois.return_value = MagicMock(domain_name=None)
        result = get_whois_info("nonexistentdomain123.com")
        self.assertIn("error", result)

    @patch('chimera_intel.core.footprint.dns.resolver.resolve')
    def test_get_dns_records_success(self, mock_resolve):
        """Tests a successful DNS resolution by mocking the dnspython library."""
        # Simulate a successful DNS resolution for an 'A' record
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "1.2.3.4"
        mock_resolve.return_value = [mock_answer]
        result = get_dns_records("google.com")
        self.assertIn("A", result)
        self.assertEqual(result["A"][0], "1.2.3.4")

    # The @patch decorator now targets the httpx.AsyncClient in the correct module
    @patch('chimera_intel.core.footprint.httpx.AsyncClient')
    def test_get_subdomains_virustotal_success(self, mock_async_client):
        """
        Tests a successful call to the asynchronous get_subdomains_virustotal function.
        This test correctly mocks the async client and asserts against the list that the function returns.
        """
        # --- Setup the mock for the async context manager ---
        # When 'async with httpx.AsyncClient() as client:' is called,
        # this mock will be returned.
        mock_client_instance = mock_async_client.return_value.__aenter__.return_value

        # --- Simulate a successful API response ---
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"id": "sub1.google.com"}, {"id": "sub2.google.com"}]
        }
        
        # --- Configure the mock client ---
        # We tell the mock client's 'get' method to be an async function (AsyncMock)
        # that returns our simulated response.
        mock_client_instance.get = AsyncMock(return_value=mock_response)

        # --- Run the async function ---
        # We use asyncio.run() to execute the coroutine and get its result.
        result = asyncio.run(get_subdomains_virustotal("google.com", "fake_api_key", mock_client_instance))

        # --- Assert against the actual returned list ---
        self.assertIsInstance(result, list, "The function should return a list.")
        self.assertEqual(len(result), 2, "The list should contain two subdomains.")
        self.assertIn("sub1.google.com", result, "The first subdomain should be in the list.")
        self.assertIn("sub2.google.com", result, "The second subdomain should be in the list.")

if __name__ == '__main__':
    unittest.main()