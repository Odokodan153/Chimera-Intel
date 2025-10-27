"""
Unit tests for the 'defensive' module.

This test suite verifies the functionality of the defensive scanning functions
in 'chimera_intel.core.defensive.py'. It uses 'unittest.mock' to simulate
responses from external APIs and command-line tools, ensuring that the tests
are reliable and do not depend on network access.
"""

import unittest
from unittest.mock import MagicMock, mock_open, patch

from chimera_intel.core.defensive import (
    analyze_apk_mobsf,
    analyze_attack_surface_shodan,
    analyze_mozilla_observatory,
    analyze_ssl_ssllabs,
    check_hibp_breaches,
    find_typosquatting_dnstwist,
    monitor_ct_logs,
    scan_for_secrets,
    scan_iac_files,
    search_github_leaks,
    search_pastes_api,
    defensive_app,
)
from chimera_intel.core.schemas import (
    GitHubLeaksResult,
    HIBPResult,
    MobSFResult,
    MozillaObservatoryResult,
    PasteResult,
    ShodanResult,
    SSLLabsResult,
    TyposquatResult,
)
from httpx import HTTPStatusError, RequestError, Response
from typer.testing import CliRunner

# CliRunner to simulate CLI commands

runner = CliRunner()


class TestDefensive(unittest.TestCase):
    """Test cases for defensive scanning functions."""

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_check_hibp_breaches_found(self, mock_get: MagicMock):
        """Tests the HIBP breach check for a successful case where breaches are found.

        Args:
            mock_get (MagicMock): A mock for the `httpx.Client.get` method.
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

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_check_hibp_breaches_not_found(self, mock_get: MagicMock):
        """Tests the HIBP breach check for a case where no breaches are found (404).

        Args:
            mock_get (MagicMock): A mock for the `httpx.Client.get` method.
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
        """Tests the HIBP check when an HTTP error (e.g., 500) occurs.

        Args:
            mock_get (MagicMock): A mock for the `httpx.Client.get` method.
        """
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
        """Tests the HIBP check during a network error.

        Args:
            mock_get (MagicMock): A mock for the `httpx.Client.get` method.
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
        """Tests the dnstwist wrapper for a successful execution.

        Args:
            mock_run (MagicMock): A mock for the `subprocess.run` function.
        """
        mock_process = MagicMock()
        mock_process.stdout = '[{"fuzzer": "Original", "domain-name": "examp1e.com"}]'
        mock_run.return_value = mock_process
        result = find_typosquatting_dnstwist("example.com")
        self.assertIsInstance(result, TyposquatResult)
        self.assertIsNotNone(result.results)

    def test_find_typosquatting_dnstwist_invalid_input(self):
        """Tests dnstwist wrapper with an invalid domain starting with a hyphen."""
        result = find_typosquatting_dnstwist("-example.com")
        self.assertIsNotNone(result.error)
        self.assertIn("Invalid domain format", result.error)

    @patch("chimera_intel.core.defensive.subprocess.run")
    def test_find_typosquatting_dnstwist_command_not_found(self, mock_run: MagicMock):
        """Tests dnstwist when the command is not found in the system.

        Args:
            mock_run (MagicMock): A mock for the `subprocess.run` function.
        """
        mock_run.side_effect = FileNotFoundError
        result = find_typosquatting_dnstwist("example.com")
        self.assertIsInstance(result, TyposquatResult)
        self.assertIn("command not found", result.error)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_search_github_leaks_success(self, mock_get: MagicMock):
        """Tests a successful GitHub leak search.

        Args:
            mock_get (MagicMock): A mock for the `httpx.Client.get` method.
        """
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
    def test_analyze_attack_surface_shodan_success(self, mock_shodan: MagicMock):
        """Tests a successful Shodan search.

        Args:
            mock_shodan (MagicMock): A mock for the `shodan.Shodan` class.
        """
        mock_api = mock_shodan.return_value
        mock_api.search.return_value = {"total": 1, "matches": [{"ip_str": "1.1.1.1"}]}
        result = analyze_attack_surface_shodan("org:Google", "fake_shodan_key")
        self.assertIsInstance(result, ShodanResult)
        self.assertEqual(result.total_results, 1)
        self.assertEqual(result.hosts[0].ip, "1.1.1.1")
        self.assertIsNone(result.error)

    def test_analyze_attack_surface_shodan_no_key(self):
        """Tests Shodan search when no API key is provided."""
        result = analyze_attack_surface_shodan("org:Google", "")
        self.assertIsInstance(result, ShodanResult)
        self.assertIsNotNone(result.error)
        self.assertIn("not found", result.error)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_search_pastes_api_success(self, mock_get: MagicMock):
        """Tests a successful paste.ee search.

        Args:
            mock_get (MagicMock): A mock for the `httpx.Client.get` method.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pastes": [{"id": "paste1", "link": "link1"}]
        }
        mock_get.return_value = mock_response
        result = search_pastes_api("example.com")
        self.assertIsInstance(result, PasteResult)
        self.assertEqual(result.count, 1)
        self.assertEqual(result.pastes[0].id, "paste1")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_search_pastes_api_http_error(self, mock_get: MagicMock):
        """Tests the paste.ee search when an HTTP error occurs.

        Args:
            mock_get (MagicMock): A mock for the `httpx.Client.get` method.
        """
        mock_response = MagicMock()
        http_error = HTTPStatusError(
            "Error", request=MagicMock(), response=Response(status_code=404)
        )
        mock_response.raise_for_status.side_effect = http_error
        mock_get.return_value = mock_response
        result = search_pastes_api("some_query")
        self.assertIsInstance(result, PasteResult)
        self.assertIsNotNone(result.error)
        self.assertIn("404", result.error)

    @patch("chimera_intel.core.defensive.sync_client.get")
    @patch("time.sleep", return_value=None)
    def test_analyze_ssl_ssllabs_success(self, mock_sleep, mock_get):
        """Tests a successful SSL Labs scan.

        Args:
            mock_sleep (MagicMock): A mock for `time.sleep`.
            mock_get (MagicMock): A mock for `httpx.Client.get`.
        """
        mock_start_response = MagicMock(status_code=200)
        mock_start_response.json.return_value = {"status": "IN_PROGRESS"}
        mock_poll_response_1 = MagicMock(status_code=200)
        mock_poll_response_1.json.return_value = {"status": "IN_PROGRESS"}
        mock_poll_response_2 = MagicMock(status_code=200)
        mock_poll_response_2.json.return_value = {"status": "READY", "grade": "A+"}
        mock_get.side_effect = [
            mock_start_response,
            mock_poll_response_1,
            mock_poll_response_2,
        ]
        result = analyze_ssl_ssllabs("example.com")
        self.assertIsInstance(result, SSLLabsResult)
        self.assertEqual(result.report.get("grade"), "A+")
        self.assertIsNone(result.error)
        self.assertEqual(mock_get.call_count, 3)

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data=b"apk_data")
    @patch("chimera_intel.core.defensive.sync_client.post")
    def test_analyze_apk_mobsf_success(self, mock_post, mock_file, mock_exists):
        """Tests a successful MobSF APK analysis.

        Args:
            mock_post (MagicMock): A mock for `httpx.Client.post`.
            mock_file (MagicMock): A mock for the `open` built-in.
            mock_exists (MagicMock): A mock for `os.path.exists`.
        """
        mock_upload_response = MagicMock(status_code=200)
        mock_upload_data = {"hash": "123", "scan_type": "apk", "file_name": "test.apk"}
        mock_upload_response.json.return_value = mock_upload_data
        mock_scan_response = MagicMock(status_code=200)
        mock_report_response = MagicMock(status_code=200)
        mock_report_response.json.return_value = {"app_name": "TestApp"}
        mock_post.side_effect = [
            mock_upload_response,
            mock_scan_response,
            mock_report_response,
        ]
        result = analyze_apk_mobsf("test.apk", "http://mobsf.local", "fake_key")
        self.assertIsInstance(result, MobSFResult)
        self.assertEqual(result.report.get("app_name"), "TestApp")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.defensive.sync_client.get")
    def test_monitor_ct_logs_success(self, mock_get):
        """Tests the Certificate Transparency log monitoring by mocking the crt.sh API.

        Args:
            mock_get (MagicMock): A mock for the `httpx.Client.get` method.
        """
        # Arrange

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = [
            {
                "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                "name_value": "test.example.com",
            }
        ]
        mock_get.return_value = mock_response

        # Act

        result = monitor_ct_logs("example.com")

        # Assert

        self.assertIsNotNone(result)
        self.assertEqual(result.total_found, 1)
        self.assertEqual(result.certificates[0].subject_name, "test.example.com")

    @patch("chimera_intel.core.defensive.subprocess.run")
    def test_scan_iac_files_success(self, mock_subprocess_run):
        """Tests the IaC scanning function by mocking the tfsec subprocess.

        Args:
            mock_subprocess_run (MagicMock): A mock for `subprocess.run`.
        """
        # Arrange

        mock_tfsec_output = """
        {
            "results": [{
                "rule_id": "AWS006",
                "description": "S3 bucket does not have encryption enabled.",
                "severity": "HIGH",
                "location": {"filename": "main.tf", "start_line": 25}
            }]
        }
        """
        mock_subprocess_run.return_value = MagicMock(
            stdout=mock_tfsec_output, stderr="", returncode=1
        )

        with patch("os.path.isdir", return_value=True):
            # Act

            result = scan_iac_files("/path/to/terraform")

            # Assert

            self.assertIsNotNone(result)
            self.assertEqual(result.total_issues, 1)
            self.assertEqual(result.issues[0].severity, "HIGH")
            self.assertEqual(result.issues[0].issue_id, "AWS006")

    @patch("chimera_intel.core.defensive.os.remove")
    @patch("chimera_intel.core.defensive.os.path.exists", return_value=True)
    @patch("chimera_intel.core.defensive.subprocess.run")
    def test_scan_for_secrets_success(
        self, mock_subprocess_run, mock_exists, mock_remove
    ):
        """Tests the secrets scanning function by mocking the gitleaks subprocess.

        Args:
            mock_subprocess_run (MagicMock): A mock for `subprocess.run`.
            mock_exists (MagicMock): A mock for `os.path.exists`.
            mock_remove (MagicMock): A mock for `os.remove`.
        """
        # Arrange

        mock_gitleaks_report = """
        [{
            "File": "config/prod.yaml",
            "RuleID": "aws-access-key",
            "Description": "AWS Access Key",
            "StartLine": 10
        }]
        """
        # Simulate gitleaks running and writing to its report file

        mock_subprocess_run.return_value = MagicMock(returncode=1)

        with patch("builtins.open", mock_open(read_data=mock_gitleaks_report)):
            with patch("os.path.isdir", return_value=True):
                # Act

                result = scan_for_secrets("/path/to/repo")

                # Assert

                self.assertIsNotNone(result)
                self.assertEqual(result.total_found, 1)
                self.assertEqual(result.secrets[0].secret_type, "AWS Access Key")
                self.assertEqual(result.secrets[0].file_path, "config/prod.yaml")
                # Verify the temporary report file was cleaned up

                mock_remove.assert_called_once_with("gitleaks-report.json")

    # --- NEW: Tests for Mozilla Observatory ---

    @patch("chimera_intel.core.defensive.sync_client.post")
    @patch("chimera_intel.core.defensive.sync_client.get")
    @patch("time.sleep", return_value=None)  # Mock sleep to make the test run instantly
    def test_analyze_mozilla_observatory_success(self, mock_sleep, mock_get, mock_post):
        """Tests a successful Mozilla Observatory scan with polling."""
        # 1. Mock the initial POST to start the scan

        mock_post_response = MagicMock(spec=Response)
        mock_post_response.raise_for_status.return_value = None
        mock_post_response.json.return_value = {"scan_id": 12345, "state": "PENDING"}
        mock_post.return_value = mock_post_response

        # 2. Mock the polling GET requests

        mock_poll_pending = MagicMock(spec=Response)
        mock_poll_pending.raise_for_status.return_value = None
        mock_poll_pending.json.return_value = {"state": "RUNNING"}

        mock_poll_finished = MagicMock(spec=Response)
        mock_poll_finished.raise_for_status.return_value = None
        mock_poll_finished.json.return_value = {
            "scan_id": 12345,
            "state": "FINISHED",
            "score": 80,
            "grade": "B",
            "tests_passed": 10,
            "tests_failed": 2,
        }
        mock_get.side_effect = [mock_poll_pending, mock_poll_finished]

        # Act

        result = analyze_mozilla_observatory("example.com")

        # Assert

        self.assertIsInstance(result, MozillaObservatoryResult)
        self.assertEqual(result.grade, "B")
        self.assertEqual(result.score, 80)
        self.assertIsNone(result.error)
        mock_post.assert_called_once()
        self.assertEqual(mock_get.call_count, 2)

    @patch("chimera_intel.core.defensive.sync_client.post")
    @patch("chimera_intel.core.defensive.sync_client.get")
    @patch("time.sleep", return_value=None)
    def test_analyze_mozilla_observatory_scan_failed(
        self, mock_sleep, mock_get, mock_post
    ):
        """Tests the handling of a 'FAILED' state from the Observatory API."""
        mock_post.return_value.json.return_value = {
            "scan_id": 12345,
            "state": "PENDING",
        }
        mock_get.return_value.json.return_value = {"state": "FAILED"}

        result = analyze_mozilla_observatory("example.com")

        self.assertIsInstance(result, MozillaObservatoryResult)
        self.assertIsNotNone(result.error)
        self.assertIn("Scan failed on the server side", result.error)

    @patch("chimera_intel.core.defensive.sync_client.post")
    def test_analyze_mozilla_observatory_api_error(self, mock_post):
        """Tests error handling when the initial API call fails."""
        mock_post.side_effect = RequestError("Connection Refused")

        result = analyze_mozilla_observatory("example.com")

        self.assertIsNone(result)

    # --- CLI COMMAND TESTS ---

    @patch("chimera_intel.core.defensive.check_hibp_breaches")
    def test_cli_breaches_invalid_domain(self, mock_check: MagicMock):
        """Tests the 'breaches' command with an invalid domain.

        Args:
            mock_check (MagicMock): A mock for `check_hibp_breaches`.
        """
        result = runner.invoke(defensive_app, ["breaches", "invalid-domain"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("is not a valid domain format", result.stdout)

    @patch("chimera_intel.core.defensive.find_typosquatting_dnstwist")
    def test_cli_typosquat_invalid_domain(self, mock_find: MagicMock):
        """Tests the 'typosquat' command with an invalid domain.

        Args:
            mock_find (MagicMock): A mock for `find_typosquatting_dnstwist`.
        """
        result = runner.invoke(defensive_app, ["typosquat", "invalid-domain"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("is not a valid domain format", result.stdout)

    @patch("chimera_intel.core.defensive.analyze_ssl_ssllabs")
    def test_cli_ssllabs_invalid_domain(self, mock_analyze: MagicMock):
        """Tests the 'ssllabs' command with an invalid domain.

        Args:
            mock_analyze (MagicMock): A mock for `analyze_ssl_ssllabs`.
        """
        result = runner.invoke(defensive_app, ["ssllabs", "invalid-domain"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("is not a valid domain format", result.stdout)

    @patch("chimera_intel.core.defensive.search_github_leaks")
    @patch("chimera_intel.core.config_loader.API_KEYS.github_pat", "fake_key")
    def test_cli_leaks_command(self, mock_pat: MagicMock, mock_search: MagicMock):
        """Tests a successful 'leaks' CLI command.

        Args:
            mock_pat (MagicMock): A mock for the patched `github_pat`.
            mock_search (MagicMock): A mock for `search_github_leaks`.
        """
        mock_search.return_value.model_dump.return_value = {"total_count": 0}
        result = runner.invoke(defensive_app, ["leaks", "query"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"total_count": 0', result.stdout)

    @patch("chimera_intel.core.config_loader.API_KEYS.github_pat", None)
    def test_cli_leaks_no_api_key_shows_warning(self):
        """Tests 'defensive leaks' prints a warning when API key is missing."""
        result = runner.invoke(defensive_app, ["leaks", "query"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Skipping GitHub Leaks Scan", result.stdout)
        self.assertIn("GITHUB_PAT", result.stdout)

    @patch("chimera_intel.core.defensive.search_pastes_api")
    def test_cli_pastebin_command(self, mock_search: MagicMock):
        """Tests a successful 'pastebin' CLI command.

        Args:
            mock_search (MagicMock): A mock for `search_pastes_api`.
        """
        mock_search.return_value.model_dump.return_value = {"count": 1, "pastes": []}
        result = runner.invoke(defensive_app, ["pastebin", "query"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"count": 1', result.stdout)

    @patch("chimera_intel.core.defensive.analyze_ssl_ssllabs")
    def test_cli_ssllabs_command_success(self, mock_analyze: MagicMock):
        """Tests a successful 'ssllabs' CLI command.

        Args:
            mock_analyze (MagicMock): A mock for `analyze_ssl_ssllabs`.
        """
        mock_analyze.return_value.model_dump.return_value = {
            "report": {"host": "example.com", "grade": "A"}
        }
        result = runner.invoke(defensive_app, ["ssllabs", "example.com"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"grade": "A"', result.stdout)

    @patch("chimera_intel.core.defensive.analyze_apk_mobsf")
    @patch("chimera_intel.core.config_loader.API_KEYS.mobsf_api_key", "fake_key")
    def test_cli_mobsf_command_success(self, mock_key: MagicMock, mock_analyze: MagicMock):
        """Tests a successful 'mobsf' CLI command.

        Args:
            mock_key (MagicMock): A mock for the patched `mobsf_api_key`.
            mock_analyze (MagicMock): A mock for `analyze_apk_mobsf`.
        """
        mock_analyze.return_value.model_dump.return_value = {
            "report": {"app_name": "TestApp"}
        }
        result = runner.invoke(defensive_app, ["mobsf", "--apk-file", "test.apk"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"app_name": "TestApp"', result.stdout)

    @patch("chimera_intel.core.config_loader.API_KEYS.mobsf_api_key", None)
    def test_cli_mobsf_no_api_key_shows_warning(self):
        """Tests 'defensive mobsf' prints a warning when API key is missing."""
        result = runner.invoke(defensive_app, ["mobsf", "--apk-file", "test.apk"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Skipping MobSF Scan", result.stdout)
        self.assertIn("MOBSF_API_KEY", result.stdout)

    @patch("chimera_intel.core.defensive.analyze_attack_surface_shodan")
    @patch("chimera_intel.core.config_loader.API_KEYS.shodan_api_key", "fake_key")
    def test_cli_surface_command(self, mock_key: MagicMock, mock_analyze: MagicMock):
        """Tests a successful 'surface' CLI command.

        Args:
            mock_key (MagicMock): A mock for the patched `shodan_api_key`.
            mock_analyze (MagicMock): A mock for `analyze_attack_surface_shodan`.
        """
        mock_analyze.return_value.model_dump.return_value = {"total_results": 1}
        result = runner.invoke(defensive_app, ["surface", "query"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"total_results": 1', result.stdout)

    @patch("chimera_intel.core.config_loader.API_KEYS.shodan_api_key", None)
    def test_cli_surface_no_api_key_shows_warning(self):
        """Tests 'defensive surface' prints a warning when API key is missing."""
        result = runner.invoke(defensive_app, ["surface", "query"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Skipping Shodan Scan", result.stdout)
        self.assertIn("SHODAN_API_KEY", result.stdout)


if __name__ == "__main__":
    unittest.main()