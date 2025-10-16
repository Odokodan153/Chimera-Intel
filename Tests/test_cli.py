"""
Tests for the main Command-Line Interface (CLI) of the Chimera Intel application.

This test suite uses Typer's CliRunner to simulate command-line inputs and verify
that the application behaves as expected, including correct command routing,
parameter validation, and output.
"""

import subprocess
import sys
import unittest
import json
from typer.testing import CliRunner
from unittest.mock import patch, AsyncMock, MagicMock
import typer
from importlib import reload

from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.footprint import footprint_app
from chimera_intel.core.defensive import defensive_app
from chimera_intel.core.schemas import (
    FootprintResult,
    FootprintData,
    SubdomainReport,
    HIBPResult,
    WhoisInfo,
    DNSRecord,
    IPThreatIntelligence,
    HistoricalDNS,
    ReverseIP,
    ASNInfo,
    TLSCertificate,
    DNSSecInfo,
    IPGeolocation,
    PortScanResult,
    WebTechnology,
    PersonnelInfo,
    KnowledgeGraph,
)

# --- Mock Plugins ---


class MockFootprintPlugin(ChimeraPlugin):
    @property
    def name(self) -> str:
        return "scan"

    @property
    def app(self) -> typer.Typer:
        plugin_app = typer.Typer()
        plugin_app.add_typer(footprint_app, name="footprint")
        return plugin_app

    def initialize(self):
        pass


class MockDefensivePlugin(ChimeraPlugin):
    @property
    def name(self) -> str:
        return "defensive"

    @property
    def app(self) -> typer.Typer:
        plugin_app = typer.Typer()
        plugin_app.add_typer(defensive_app, name="checks")
        return plugin_app

    def initialize(self):
        pass


class TestCLI(unittest.IsolatedAsyncioTestCase):
    """Tests for the main CLI with mocked plugins and database."""

    app: typer.Typer
    runner: CliRunner

    @patch("chimera_intel.cli.initialize_database")
    @patch(
        "chimera_intel.cli.discover_plugins",
        return_value=[MockFootprintPlugin(), MockDefensivePlugin()],
    )
    def setUp(self, mock_discover_plugins, mock_initialize_database):
        """
        This method runs before each test. It reloads the CLI with mocked plugins.
        """
        import chimera_intel.cli

        reload(chimera_intel.cli)

        self.app = chimera_intel.cli.get_cli_app()

        # Manually add the mocked plugins to self.app for testing

        for plugin in mock_discover_plugins.return_value:
            self.app.add_typer(plugin.app, name=plugin.name)
        self.runner = CliRunner()

    def test_main_app_help(self):
        """Tests that the --help command works and displays commands from plugins."""
        result = self.runner.invoke(self.app, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Usage", result.stdout)
        # Check that commands from both mocked plugins are present

        self.assertIn("scan", result.stdout)
        self.assertIn("defensive", result.stdout)

    def test_version_command(self):
        """Tests the version command."""
        result = self.runner.invoke(self.app, ["version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Chimera Intel v1.0.0", result.stdout)

    @patch(
        "chimera_intel.cli.initialize_database", side_effect=ConnectionError("DB Down")
    )
    def test_main_no_db_connection_still_runs_basic_commands(
        self, mock_initialize_database
    ):
        """Tests that the CLI can still run basic commands like --help without a DB connection."""
        result = self.runner.invoke(self.app, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Usage", result.stdout)

    def test_main_script_entry_point(self):
        """Tests running the CLI script as a subprocess to ensure it's executable."""
        with patch.dict("os.environ", {"PYTHONPATH": "."}):
            result = subprocess.run(
                [sys.executable, "-m", "chimera_intel.cli", "--help"],
                capture_output=True,
                text=True,
            )
        self.assertEqual(
            result.returncode,
            0,
            f"Subprocess failed with stderr: {result.stderr}",
        )
        self.assertIn("Usage", result.stdout)

    # --- Plugin Command Tests ---

    @patch("chimera_intel.core.footprint.gather_footprint_data", new_callable=AsyncMock)
    async def test_scan_footprint_success(self, mock_gather_footprint: AsyncMock):
        """Tests a successful 'scan footprint run' command with specific assertions."""
        # Arrange

        mock_result_model = FootprintResult(
            domain="example.com",
            footprint=FootprintData(
                whois_info=WhoisInfo(domain_name="example.com"),
                dns_records=[DNSRecord(record_type="A", value="127.0.0.1")],
                subdomains=SubdomainReport(total_unique=0, results=[]),
                ip_threat_intelligence=[
                    IPThreatIntelligence(ip_address="127.0.0.1", threat_level="low")
                ],
                historical_dns=[HistoricalDNS(record_type="A", value="127.0.0.1")],
                reverse_ip=[ReverseIP(hostname="localhost")],
                asn_info=ASNInfo(asn="AS12345"),
                tls_cert_info=TLSCertificate(issuer="Test CA"),
                dnssec_info=DNSSecInfo(is_enabled=False),
                ip_geolocation=IPGeolocation(country="Testland"),
                breach_info=HIBPResult(breaches=[]),
                port_scan_results=[PortScanResult(port=80, status="open")],
                web_technologies=[WebTechnology(name="TestWeb", version="1.0")],
                personnel_info=[PersonnelInfo(name="John Doe")],
                knowledge_graph=KnowledgeGraph(entities=[], relationships=[]),
            ),
        )
        mock_gather_footprint.return_value = mock_result_model

        # Act

        result = self.runner.invoke(
            self.app, ["scan", "footprint", "run", "example.com"]
        )

        # Assert

        self.assertEqual(result.exit_code, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["domain"], "example.com")
        self.assertIn("footprint", output)

    def test_scan_footprint_invalid_domain(self):
        """Tests 'scan footprint run' with an invalid domain, expecting a specific error."""
        # Act

        result = self.runner.invoke(
            self.app, ["scan", "footprint", "run", "invalid-domain"]
        )

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("is not a valid domain format", result.stdout)

    @patch("chimera_intel.core.defensive.check_hibp_breaches")
    def test_defensive_breaches_success(self, mock_check_hibp: MagicMock):
        """Tests a successful 'defensive checks breaches' command."""
        # Arrange

        mock_check_hibp.return_value = HIBPResult(breaches=[])

        with patch(
            "chimera_intel.core.config_loader.API_KEYS.hibp_api_key", "fake_key"
        ):
            # Act

            result = self.runner.invoke(
                self.app, ["defensive", "checks", "breaches", "mycompany.com"]
            )
        # Assert

        self.assertEqual(result.exit_code, 0)
        # Extract the JSON part of the output for validation

        json_output_str = result.stdout.splitlines()[-1]
        output = json.loads(json_output_str)
        self.assertEqual(output["breaches"], [])

    @patch("chimera_intel.core.config_loader.API_KEYS.hibp_api_key", None)
    def test_defensive_breaches_no_api_key(self):
        """Tests 'defensive checks breaches' when the API key is missing, expecting a graceful skip."""
        # Act

        result = self.runner.invoke(
            self.app, ["defensive", "checks", "breaches", "mycompany.com"]
        )

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Skipping HIBP Scan", result.stdout)


if __name__ == "__main__":
    unittest.main()
