import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner

from chimera_intel.core.cybint import cybint_app  # Import the specific app
from chimera_intel.core.cybint import (
    generate_attack_surface_report,
)
from chimera_intel.core.schemas import (
    MozillaObservatoryResult,
    AttackSurfaceReport,
    FootprintResult,
    VulnerabilityScanResult,
    APIDiscoveryResult,
    ProjectConfig,
    FootprintData,
    SubdomainReport,
)

runner = CliRunner(mix_stderr=False)


class TestCybint(unittest.IsolatedAsyncioTestCase):
    """Test cases for the Cyber Intelligence (CYBINT) module."""

    @patch("chimera_intel.core.cybint.gather_footprint_data", new_callable=AsyncMock)
    @patch("chimera_intel.core.cybint.run_vulnerability_scan")
    @patch("chimera_intel.core.cybint.discover_apis", new_callable=AsyncMock)
    @patch("chimera_intel.core.cybint.analyze_mozilla_observatory")
    async def test_generate_attack_surface_report(
        self,
        mock_mozilla_scan: MagicMock,
        mock_api_discover: AsyncMock,
        mock_vuln_scan: MagicMock,
        mock_footprint: AsyncMock,
    ):
        """Tests the main report generation orchestrator by mocking its sub-scans."""
        # Arrange: Mock the return values of all the individual scans

        mock_footprint_result = MagicMock(spec=FootprintResult)
        mock_footprint_data = MagicMock(spec=FootprintData)
        mock_subdomain_report = MagicMock(spec=SubdomainReport)
        mock_subdomain_report.total_unique = 0
        mock_footprint_data.subdomains = mock_subdomain_report
        mock_footprint_data.dns_records = {"A": ["1.2.3.4"]}
        mock_footprint_data.ip_threat_intelligence = []
        mock_footprint_result.footprint = mock_footprint_data
        mock_footprint.return_value = mock_footprint_result

        mock_vuln_scan.return_value = MagicMock(spec=VulnerabilityScanResult)
        mock_vuln_scan.return_value.scanned_hosts = []
        mock_api_discover.return_value = MagicMock(spec=APIDiscoveryResult)
        mock_api_discover.return_value.discovered_apis = []

        # FIX: Ensure the mock object has the 'grade' attribute

        mock_mozilla_result = MagicMock(spec=MozillaObservatoryResult)
        mock_mozilla_result.grade = "A"
        mock_mozilla_result.score = 100
        mock_mozilla_scan.return_value = mock_mozilla_result

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
    @patch("chimera_intel.core.cybint.save_scan_to_db")
    def test_cli_attack_surface_success_with_arg(
        self, mock_save_db, mock_generate_report: AsyncMock
    ):
        """Tests the CLI command with an explicit domain argument."""
        # Arrange

        mock_result = MagicMock(spec=AttackSurfaceReport)
        mock_result.model_dump.return_value = {"target_domain": "cli-test.com"}
        mock_result.ai_risk_assessment = "AI RISK ASSESSMENT"
        mock_generate_report.return_value = mock_result

        # Act

        result = runner.invoke(cybint_app, ["cli-test.com"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Attack Surface Risk Assessment for: cli-test.com", result.stdout)
        self.assertIn("AI RISK ASSESSMENT", result.stdout)
        mock_generate_report.assert_awaited_with("cli-test.com")
        mock_save_db.assert_called_once()

    @patch("chimera_intel.core.cybint.get_active_project")
    @patch(
        "chimera_intel.core.cybint.generate_attack_surface_report",
        new_callable=AsyncMock,
    )
    @patch("chimera_intel.core.cybint.save_scan_to_db")
    def test_cli_attack_surface_with_active_project(
        self, mock_save_db, mock_generate_report: AsyncMock, mock_get_project: MagicMock
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
        mock_result.ai_risk_assessment = "AI RISK ASSESSMENT"
        mock_generate_report.return_value = mock_result

        # Act

        result = runner.invoke(cybint_app, [])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn(
            "Using domain 'project-cybint.com' from active project", result.stdout
        )
        self.assertIn(
            "Attack Surface Risk Assessment for: project-cybint.com", result.stdout
        )
        mock_generate_report.assert_awaited_with("project-cybint.com")
        mock_save_db.assert_called_once()

    @patch("chimera_intel.core.cybint.get_active_project")
    def test_cli_attack_surface_no_domain_no_project(self, mock_get_project: MagicMock):
        """Tests the CLI fails when no domain is provided and no project is active."""
        # Arrange

        mock_get_project.return_value = None

        # Act

        result = runner.invoke(cybint_app, [])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("No domain provided and no active project set", result.stdout)


if __name__ == "__main__":
    unittest.main()
