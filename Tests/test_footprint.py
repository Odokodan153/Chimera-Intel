import unittest
from unittest.mock import patch, MagicMock
from modules.footprint import is_valid_domain, get_whois_info, get_dns_records, get_subdomains_virustotal

class TestFootprint(unittest.TestCase):

    def test_is_valid_domain(self):
        self.assertTrue(is_valid_domain("google.com"))
        self.assertTrue(is_valid_domain("sub.domain.co.uk"))
        self.assertFalse(is_valid_domain("invalid-domain"))
        self.assertFalse(is_valid_domain("google.c"))
        self.assertFalse(is_valid_domain("-google.com"))

    @patch('modules.footprint.whois.whois')
    def test_get_whois_info_success(self, mock_whois):
        # Simulate a successful WHOIS lookup
        mock_whois.return_value = MagicMock(domain_name="google.com", registrar="MarkMonitor Inc.")
        result = get_whois_info("google.com")
        self.assertEqual(result.get('registrar'), "MarkMonitor Inc.")

    @patch('modules.footprint.whois.whois')
    def test_get_whois_info_failure(self, mock_whois):
        # Simulate a failed WHOIS lookup (e.g., domain not found)
        mock_whois.return_value = MagicMock(domain_name=None)
        result = get_whois_info("nonexistentdomain123.com")
        self.assertIn("error", result)

    @patch('modules.footprint.dns.resolver.resolve')
    def test_get_dns_records_success(self, mock_resolve):
        # Simulate a successful DNS resolution
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "1.2.3.4"
        mock_resolve.return_value = [mock_answer]
        result = get_dns_records("google.com")
        self.assertIn("A", result)
        self.assertEqual(result["A"][0], "1.2.3.4")

    @patch('modules.footprint.requests.get')
    def test_get_subdomains_virustotal_success(self, mock_get):
        # Simulate a successful VirusTotal API call
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"id": "sub1.google.com"}, {"id": "sub2.google.com"}]
        }
        mock_get.return_value = mock_response
        result = get_subdomains_virustotal("google.com", "fake_api_key")
        self.assertEqual(result.get("count"), 2)
        self.assertIn("sub1.google.com", result.get("subdomains"))

if __name__ == '__main__':
    unittest.main()