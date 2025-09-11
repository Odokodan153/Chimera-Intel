import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner

from chimera_intel.cli import app
from chimera_intel.core.cybint import (
    get_mozilla_observatory_scan,
    generate_attack_surface_report,
)
from chimera_intel.core.schemas import (
    MozillaObservatoryResult,
    AttackSurfaceReport,
    FootprintResult,
    VulnerabilityScanResult,
    APIDiscoveryResult,
    ProjectConfig,
)

runner = CliRunner()


class TestCybint(unittest.IsolatedAsyncioTestCase):
    """Test cases for the Cyber Intelligence (CYBINT) module."""

    @patch("chimera_intel.core.cybint.sync_client")
    @patch("chimera_intel.core.cybint.asyncio.sleep", new_callable=AsyncMock)
    def test_get_mozilla_observatory_scan_success(self, mock_sleep, mock_sync_client):
        """Tests a successful Mozilla Observatory scan, including the polling mechanism."""
        # Arrange: Mock the API responses for POST (initiate) and GET (poll)

        mock_post_response = MagicMock()
        mock_post_response.raise_for_status.return_value = None
        mock_post_response.json.return_value = {"state": "RUNNING"}

        mock_get_response_running = MagicMock()
        mock_get_response_running.raise_for_status.return_value = None
        mock_get_response_running.json.return_value = {"state": "RUNNING"}

        mock_get_response_finished = MagicMock()
        mock_get_response_finished.raise_for_status.return_value = None
        mock_get_response_finished.json.return_value = {
            "scan_id": 12345,
            "state": "FINISHED",
            "grade": "A+",
            "score": 120,
            "tests_passed": 12,
            "tests_failed": 0,
        }

        mock_sync_client.post.return_value = mock_post_response
        mock_sync_client.get.side_effect = [
            mock_get_response_running,
            mock_get_response_finished,
        ]

        # Act

        result = get_mozilla_observatory_scan("example.com")

        # Assert

        self.assertIsInstance(result, MozillaObservatoryResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.grade, "A+")
        self.assertEqual(result.score, 120)
        self.assertEqual(mock_sync_client.post.call_count, 1)
        self.assertEqual(mock_sync_client.get.call_count, 2)

    @patch("chimera_intel.core.cybint.gather_footprint_data", new_callable=AsyncMock)
    @patch("chimera_intel.core.cybint.run_vulnerability_scan")
    @patch("chimera_intel.core.cybint.discover_apis", new_callable=AsyncMock)
    @patch("chimera_intel.core.cybint.get_mozilla_observatory_scan")
    async def test_generate_attack_surface_report(
        self,
        mock_mozilla_scan,
        mock_api_discover,
        mock_vuln_scan,
        mock_footprint,
    ):
        """Tests the main report generation orchestrator by mocking its sub-scans."""
        # Arrange: Mock the return values of all the individual scans

        mock_footprint.return_value = MagicMock(spec=FootprintResult)
        mock_vuln_scan.return_value = MagicMock(spec=VulnerabilityScanResult)
        mock_api_discover.return_value = MagicMock(spec=APIDiscoveryResult)
        mock_mozilla_scan.return_value = MagicMock(spec=MozillaObservatoryResult)

        # Act

        result = await generate_attack_surface_report("example.com")

        # Assert

        self.assertIsInstance(result, AttackSurfaceReport)
        self.assertEqual(result.target_domain, "example.com")
        self.assertIsNotNone(result.full_footprint_data)
        self.assertIsNotNone(result.vulnerability_scan_results)
        self.assertIsNotNone(result.api_discovery_results)
        self.assertIsNotNone(result.web_security_posture)
        mock_footprint.assert_awaited_once()
        mock_vuln_scan.assert_called_once()
        mock_api_discover.assert_awaited_once()
        mock_mozilla_scan.assert_called_once()

    # --- CLI Command Tests ---

    @patch(
        "chimera_intel.core.cybint.generate_attack_surface_report",
        new_callable=AsyncMock,
    )
    def test_cli_attack_surface_success_with_arg(self, mock_generate_report):
        """Tests the CLI command with an explicit domain argument."""
        # Arrange

        mock_result = MagicMock(spec=AttackSurfaceReport)
        mock_result.model_dump.return_value = {"target_domain": "cli-test.com"}
        mock_generate_report.return_value = mock_result

        # Act

        result = runner.invoke(app, ["cybint", "attack-surface", "cli-test.com"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn('"target_domain": "cli-test.com"', result.stdout)
        mock_generate_report.assert_awaited_with("cli-test.com")

    @patch("chimera_intel.core.cybint.get_active_project")
    @patch(
        "chimera_intel.core.cybint.generate_attack_surface_report",
        new_callable=AsyncMock,
    )
    def test_cli_attack_surface_with_active_project(
        self, mock_generate_report, mock_get_project
    ):
        """Tests the CLI command using an active project's context."""
        # Arrange

        mock_project = ProjectConfig(
            project_name="CybintTest",
            created_at="2025-01-01",
            domain="project-cybint.com",
        )
        mock_get_project.return_value = mock_project

        mock_result = MagicMock(spec=AttackSurfaceReport)
        mock_result.model_dump.return_value = {"target_domain": "project-cybint.com"}
        mock_generate_report.return_value = mock_result

        # Act

        result = runner.invoke(app, ["cybint", "attack-surface"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Using domain 'project-cybint.com'", result.stdout)
        self.assertIn('"target_domain": "project-cybint.com"', result.stdout)
        mock_generate_report.assert_awaited_with("project-cybint.com")

    @patch("chimera_intel.core.cybint.get_active_project")
    def test_cli_attack_surface_no_domain_no_project(self, mock_get_project):
        """Tests the CLI fails when no domain is provided and no project is active."""
        # Arrange

        mock_get_project.return_value = None

        # Act

        result = runner.invoke(app, ["cybint", "attack-surface"])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("No domain provided and no active project set", result.stdout)


if __name__ == "__main__":
    unittest.main()
