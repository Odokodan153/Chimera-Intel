# FILE: Chimera-Intel/Tests/test_opsec_analyzer.py
import unittest
import pytest
from datetime import datetime
from unittest.mock import patch, AsyncMock
from typer.testing import CliRunner
import typer  # Import typer

from chimera_intel.core.opsec_analyzer import generate_opsec_report, opsec_app
# NOTE: You must update OpsecReport in schemas.py to include the new fields
from chimera_intel.core.schemas import (
    OpsecReport, 
    CompromisedCommitter,
    CodeIntelResult,
    SocialOSINTResult,
    FootprintResult,
    CodeRepository,
    Committer,
    SocialProfile,
    Footprint
)
from chimera_intel.core.opsec_analyzer import _generate_footprint_report

runner = CliRunner()

# Create a top-level app and add the app-under-test as a subcommand
app = typer.Typer()
app.add_typer(opsec_app, name="opsec")


class TestOpsecAnalyzer(unittest.TestCase):
    """Test cases for the Operational Security (OPSEC) Analysis module."""

    # --- Function Tests for 'run' command ---

    @patch("chimera_intel.core.opsec_analyzer.get_aggregated_data_for_target")
    @patch("chimera_intel.core.opsec_analyzer.calculate_risk_level")
    def test_generate_opsec_report_full_risk(self, mock_calc_risk, mock_get_agg_data):
        """Tests the detection and scoring of multiple risk factors."""
        # Arrange
        mock_calc_risk.return_value = "High"
        mock_get_agg_data.return_value = {
            "target": "example.com",
            "modules": {
                "code_intel_repo": {
                    "repository_url": "http://github.com/example/repo",
                    "top_committers": [{"email": "dev@example.com"}],
                    "exposed_secrets": [{"type": "aws_key", "line": 50}],
                },
                "defensive_breaches": {
                    "breaches": [{"Name": "Breach1", "DataClasses": ["dev@example.com"]}]
                },
                "footprint": {
                    "subdomains": {"total": 51}
                },
                "vulnerability_scanner": {
                    "scanned_hosts": [{
                        "host": "1.2.3.4",
                        "open_ports": [{"port": 443, "vulnerabilities": [
                            {"cve": "CVE-2023-1234", "severity": "critical"}
                        ]}]
                    }]
                }
            },
        }

        # Act
        result = generate_opsec_report("example.com")

        # Assert
        self.assertIsInstance(result, OpsecReport)
        self.assertIsNone(result.error)
        
        # Check compromised committer (existing)
        self.assertEqual(len(result.compromised_committers), 1)
        self.assertEqual(result.compromised_committers[0].email, "dev@example.com")
        self.assertEqual(result.compromised_committers[0].related_breaches, ["Breach1"])
        
        # Check scoring (new)
        # Score = 100
        # - 15 (1 compromised dev)
        # - 10 (1 exposed secret)
        # - 10 (51 subdomains)
        # - 15 (1 critical vuln)
        # Total = 100 - 15 - 10 - 10 - 15 = 50.0
        self.assertEqual(result.opsec_score, 50.0)
        self.assertEqual(result.risk_level, "High")
        self.assertEqual(len(result.risk_factors), 4)
        self.assertIn("1 developer account(s) found in known data breaches.", result.risk_factors)
        self.assertIn("1 exposed secret(s) (API keys, etc.) found in code.", result.risk_factors)
        self.assertIn("Large external footprint (51 subdomains) increases attack surface.", result.risk_factors)
        self.assertIn("1 critical-severity vulnerability/vulnerabilities found on public hosts.", result.risk_factors)

    @patch("chimera_intel.core.opsec_analyzer.get_aggregated_data_for_target")
    @patch("chimera_intel.core.opsec_analyzer.calculate_risk_level")
    def test_generate_opsec_report_no_findings(self, mock_calc_risk, mock_get_agg_data):
        """Tests the report generation when no OPSEC issues are found."""
        # Arrange
        mock_calc_risk.return_value = "Low"
        mock_get_agg_data.return_value = {
            "target": "example.com",
            "modules": {
                "code_intel_repo": {"top_committers": [{"email": "safe@example.com"}]},
                "defensive_breaches": {"breaches": []},
                "footprint": {"subdomains": {"total": 10}},
                "social_osint": {"profiles": []}
            },
        }

        # Act
        result = generate_opsec_report("example.com")

        # Assert
        self.assertEqual(len(result.compromised_committers), 0)
        self.assertIsNone(result.error)
        # Check scoring (new)
        self.assertEqual(result.opsec_score, 100.0)
        self.assertEqual(result.risk_level, "Low")
        self.assertEqual(len(result.risk_factors), 0)

    @patch("chimera_intel.core.opsec_analyzer.get_aggregated_data_for_target")
    def test_generate_opsec_report_no_data(self, mock_get_agg_data):
        """Tests report generation when no historical data is available."""
        # Arrange
        mock_get_agg_data.return_value = None

        # Act
        result = generate_opsec_report("example.com")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("No historical data found", result.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.opsec_analyzer.resolve_target")
    @patch("chimera_intel.core.opsec_analyzer.generate_opsec_report")
    @patch("chimera_intel.core.opsec_analyzer.save_scan_to_db")
    @patch("chimera_intel.core.opsec_analyzer.save_or_print_results")
    def test_cli_opsec_run_success(
        self, mock_save_print, mock_save_db, mock_generate, mock_resolve
    ):
        """Tests a successful run of the 'opsec run' CLI command."""
        # Arrange
        mock_resolve.return_value = "example.com"
        report = OpsecReport(
            target="example.com",
            compromised_committers=[
                CompromisedCommitter(email="test@example.com", related_breaches=[])
            ],
            opsec_score=85.0, # 100 - 15
            risk_level="Medium",
            risk_factors=["1 developer account(s) found in known data breaches."]
        )
        mock_generate.return_value = report
        expected_dict = report.model_dump(exclude_none=True)

        # Act
        result = runner.invoke(app, ["opsec", "run", "--target", "example.com"])

        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIsNone(result.exception)
        self.assertIn("Risk Score: 85.0/100.0", result.stdout) # Check pretty print
        self.assertIn("Risk Level: Medium", result.stdout)
        self.assertIn("test@example.com", result.stdout)
        
        mock_generate.assert_called_with("example.com")
        mock_save_print.assert_called_with(expected_dict, None, print_to_console=False)
        mock_save_db.assert_called_with(
            target="example.com", module="opsec_report", data=expected_dict
        )

    # --- NEW TEST for 'footprint' command ---
    @patch("chimera_intel.core.opsec_analyzer.resolve_target")
    @patch("chimera_intel.core.opsec_analyzer.get_project_assets")
    @patch("chimera_intel.core.opsec_analyzer.asyncio.run")
    @patch("chimera_intel.core.opsec_analyzer.save_or_print_results")
    @patch("chimera_intel.core.opsec_analyzer.save_scan_to_db")
    def test_cli_opsec_footprint_run_success(
        self, mock_save_db, mock_save_print, mock_asyncio_run, mock_get_assets, mock_resolve
    ):
        """Tests a successful run of the 'opsec footprint' CLI command."""
        # Arrange
        mock_resolve.return_value = "TestCorp"
        mock_get_assets.side_effect = [
            ["testcorp.com"],  # First call (domains)
            ["@testcorp"]      # Second call (social)
        ]
        
        mock_report = {
            "organization": "TestCorp",
            "report_path": "reports/opsec_footprint_testcorp.json",
            "exposures": {
                "code": {"secrets_found": 1, "status": "completed"},
                "social": {"profiles_found": 5, "status": "completed"},
                "domain": {"subdomain_count": 10, "status": "completed"}
            }
        }
        mock_asyncio_run.return_value = mock_report
        
        # Act
        result = runner.invoke(app, ["opsec", "footprint", "--target", "TestCorp"])
        
        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        mock_resolve.assert_called_once_with("TestCorp", required_assets=["company_name", "domain"])
        self.assertEqual(mock_get_assets.call_count, 2)
        
        # Check that asyncio.run was called with the correct report generator
        mock_asyncio_run.assert_called_once()
        # Check that the first argument to asyncio.run was our generator function
        self.assertEqual(mock_asyncio_run.call_args[0][0].__name__, "_generate_footprint_report")
        
        # Check that the summary is saved
        expected_summary = {
            "target": "TestCorp",
            "report_path": "reports/opsec_footprint_testcorp.json",
            "code_secrets": 1,
            "social_profiles": 5,
            "subdomains": 10
        }
        mock_save_print.assert_called_with(expected_summary, None)
        mock_save_db.assert_called_with(
            target="TestCorp", module="opsec_footprint_report", data=expected_summary
        )

# --- Pytest-specific tests for async helper ---
@pytest.mark.asyncio
@patch("chimera_intel.core.opsec_analyzer.search_repositories", new_callable=AsyncMock)
@patch("chimera_intel.core.opsec_analyzer.search_profiles", new_callable=AsyncMock)
@patch("chimera_intel.core.opsec_analyzer.gather_footprint_data", new_callable=AsyncMock)
async def test_generate_footprint_report_async(
    mock_gather_footprint, mock_search_profiles, mock_search_repos, tmp_path
):
    """
    Tests the internal async helper function `_generate_footprint_report`
    using pytest-asyncio.
    """
    # Arrange
    from chimera_intel.core.schemas import Organization
    mock_org = Organization(
        name="TestCorp",
        domains=["testcorp.com"],
        social_media_handles=["@testcorp"]
    )
    
    # Mock return values for each data-gathering function
    mock_search_repos.return_value = CodeIntelResult(
        query="TestCorp", 
        repositories=[CodeRepository(
            name="repo1", url="...", exposed_secrets=[{}], top_committers=[]
        )]
    )
    mock_search_profiles.return_value = SocialOSINTResult(
        profiles=[SocialProfile(username="@testcorp", platform="Twitter", url="...")]
    )
    mock_gather_footprint.return_value = FootprintResult(
        target="testcorp.com", 
        footprint=Footprint(subdomains={"total": 5}, open_ports=[], technologies=[])
    )

    # Act
    report = await _generate_footprint_report(mock_org, tmp_path)

    # Assert
    assert report["organization"] == "TestCorp"
    assert report["exposures"]["code"]["secrets_found"] == 1
    assert report["exposures"]["social"]["profiles_found"] == 1
    assert report["exposures"]["domain"]["subdomain_count"] == 5
    assert (tmp_path / f"opsec_footprint_testcorp_{datetime.now().strftime('%Y%m%d')}.json").exists()


if __name__ == "__main__":
    unittest.main()