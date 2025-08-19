"""
Unit tests for the 'defensive' module.
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import subprocess
from httpx import RequestError, HTTPStatusError, Response
from typer.testing import CliRunner

# Import the main app to test commands

from chimera_intel.cli import app
from chimera_intel.core.defensive import (
    check_hibp_breaches,
    find_typosquatting_dnstwist,
    search_github_leaks,
    analyze_attack_surface_shodan,
    search_pastes_api,
    analyze_ssl_ssllabs,
    analyze_apk_mobsf,
)
from chimera_intel.core.schemas import HIBPResult, TyposquatResult, GitHubLeaksResult

# CliRunner to simulate CLI commands

runner = CliRunner()


class TestDefensive(unittest.TestCase):
    """Test cases for defensive scanning functions."""

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_check_hibp_breaches_found(self, mock_get: MagicMock):
        """Tests the HIBP breach check for a successful case where breaches are found."""
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

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_check_hibp_breaches_not_found(self, mock_get: MagicMock):
        """Tests the HIBP breach check for a case where no breaches are found (404)."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = check_hibp_breaches("example.com", "fake_api_key")
        self.assertIsInstance(result, HIBPResult)
        self.assertEqual(result.breaches, [])
        self.assertIn("No breaches found", result.message)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_check_hibp_breaches_http_error(self, mock_get: MagicMock):
        """Tests the HIBP check when an HTTP error (e.g., 500) occurs."""
        mock_response = MagicMock()
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
        """Tests the HIBP check during a network error."""
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
        """Tests the dnstwist wrapper for a successful execution."""
        mock_process = MagicMock()
        mock_process.stdout = '[{"fuzzer": "Original", "domain-name": "examp1e.com"}]'
        mock_run.return_value = mock_process

        result = find_typosquatting_dnstwist("example.com")
        self.assertIsInstance(result, TyposquatResult)
        self.assertIsNotNone(result.results)

    @patch("chimera_intel.core.defensive.subprocess.run")
    def test_find_typosquatting_dnstwist_command_not_found(self, mock_run: MagicMock):
        """Tests dnstwist when the command is not found in the system."""
        mock_run.side_effect = FileNotFoundError
        result = find_typosquatting_dnstwist("example.com")
        self.assertIsInstance(result, TyposquatResult)
        self.assertIn("command not found", result.error)

    @patch("chimera_intel.core.defensive.subprocess.run")
    def test_find_typosquatting_dnstwist_called_process_error(
        self, mock_run: MagicMock
    ):
        """Tests dnstwist when the command returns a non-zero exit code."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "dnstwist", stderr="Some error"
        )
        result = find_typosquatting_dnstwist("example.com")
        self.assertIsInstance(result, TyposquatResult)
        self.assertIn("returned an error", result.error)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_search_github_leaks_success(self, mock_get: MagicMock):
        """Tests a successful GitHub leak search."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "total_count": 1,
            "items": [{"url": "http://leak.com", "repository": "test/repo"}],
        }
        mock_get.return_value = mock_response

        result = search_github_leaks("example.com api_key", "fake_pat")
        self.assertIsInstance(result, GitHubLeaksResult)
        self.assertEqual(result.total_count, 1)

    def test_search_github_leaks_no_api_key(self):
        """Tests the GitHub search without an API key."""
        result = search_github_leaks("query", "")
        self.assertIsInstance(result, GitHubLeaksResult)
        self.assertIn("not found", result.error)

    @patch("shodan.Shodan")
    def test_analyze_attack_surface_shodan_success(self, mock_shodan):
        """Tests a successful Shodan search."""
        mock_api = mock_shodan.return_value
        mock_api.search.return_value = {"total": 1, "matches": [{"ip_str": "1.1.1.1"}]}

        result = analyze_attack_surface_shodan("org:Google", "fake_shodan_key")
        self.assertEqual(result["total_results"], 1)
        self.assertEqual(result["hosts"][0]["ip"], "1.1.1.1")

    def test_analyze_attack_surface_shodan_no_key(self):
        """Tests Shodan search when no API key is provided."""
        result = analyze_attack_surface_shodan("org:Google", "")
        self.assertIn("error", result)
        self.assertIn("not found", result["error"])

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_search_pastes_api_success(self, mock_get):
        """Tests a successful paste.ee search."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"pastes": [{"id": "paste1"}]}
        mock_get.return_value = mock_response

        result = search_pastes_api("example.com")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["pastes"][0]["id"], "paste1")

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_search_pastes_api_http_error(self, mock_get):
        """Tests the paste.ee search when an HTTP error occurs."""
        mock_response = MagicMock()
        http_error = HTTPStatusError(
            "Error", request=MagicMock(), response=Response(status_code=404)
        )
        mock_response.raise_for_status.side_effect = http_error
        mock_get.return_value = mock_response

        result = search_pastes_api("some_query")
        self.assertIn("error", result)
        self.assertIn("404", result["error"])

    # --- NEW TESTS FOR CLI COMMANDS ---

    @patch("chimera_intel.core.defensive.check_hibp_breaches")
    def test_cli_breaches_invalid_domain(self, mock_check):
        """Tests the 'breaches' command with an invalid domain."""
        result = runner.invoke(app, ["defensive", "breaches", "invalid-domain"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("not a valid domain format", result.stdout)

    @patch("chimera_intel.core.defensive.find_typosquatting_dnstwist")
    def test_cli_typosquat_invalid_domain(self, mock_find):
        """Tests the 'typosquat' command with an invalid domain."""
        result = runner.invoke(app, ["defensive", "typosquat", "invalid-domain"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("not a valid domain format", result.stdout)

    @patch("chimera_intel.core.defensive.analyze_ssl_ssllabs")
    def test_cli_ssllabs_invalid_domain(self, mock_analyze):
        """Tests the 'ssllabs' command with an invalid domain."""
        result = runner.invoke(app, ["defensive", "ssllabs", "invalid-domain"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("not a valid domain format", result.stdout)

    @patch("chimera_intel.core.defensive.search_github_leaks")
    @patch("chimera_intel.core.config_loader.API_KEYS.github_pat", "fake_key")
    def test_cli_leaks_command(self, mock_search):
        """Tests a successful 'leaks' CLI command."""
        mock_search.return_value.model_dump.return_value = {"total_count": 0}
        result = runner.invoke(app, ["defensive", "leaks", "query"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"total_count": 0', result.stdout)


if __name__ == "__main__":
    unittest.main()
