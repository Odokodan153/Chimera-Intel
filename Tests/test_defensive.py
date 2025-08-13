import unittest
from unittest.mock import patch, MagicMock
from chimera_intel.core.defensive import check_hibp_breaches, find_typosquatting_dnstwist

class TestDefensive(unittest.TestCase):

    @patch('chimera_intel.core.defensive.requests.get')
    def test_check_hibp_breaches_found(self, mock_get):
        # Simulate finding breaches
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"Name": "Breach1"}]
        mock_get.return_value = mock_response
        result = check_hibp_breaches("example.com", "fake_api_key")
        self.assertEqual(len(result["breaches"]), 1)

    @patch('chimera_intel.core.defensive.requests.get')
    def test_check_hibp_breaches_not_found(self, mock_get):
        # Simulate finding no breaches (404 status code)
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        result = check_hibp_breaches("example.com", "fake_api_key")
        self.assertEqual(len(result["breaches"]), 0)

    @patch('chimera_intel.core.defensive.subprocess.run')
    def test_find_typosquatting_dnstwist_success(self, mock_run):
        # Simulate a successful dnstwist run
        mock_process = MagicMock()
        mock_process.stdout = '[{"domain-name": "examp1e.com"}]'
        mock_run.return_value = mock_process
        result = find_typosquatting_dnstwist("example.com")
        self.assertEqual(result[0]["domain-name"], "examp1e.com")

if __name__ == '__main__':
    unittest.main()