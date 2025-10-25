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
    HistoricalDns,
    AsnInfo,
    TlsCertInfo,
    DnssecInfo,
    IpGeolocation,
    PortScanResult,
    WebTechInfo,
    PersonnelInfo,
    KnowledgeGraph,
    ThreatIntelResult,
    BreachInfo,
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


# --- FIX: Change from IsolatedAsyncioTestCase to TestCase ---
class TestCLI(unittest.TestCase):
    """Tests for the main CLI with mocked plugins and database."""

    app: typer.Typer
    runner: CliRunner

    # --- FIX: Patches must target the *original source* module ---
    @patch("chimera_intel.core.database.initialize_database")
    @patch(
        "chimera_intel.core.plugin_manager.discover_plugins",
        return_value=[MockFootprintPlugin(), MockDefensivePlugin()],
    )
    def setUp(self, mock_discover_plugins, mock_initialize_database):
        """
        This method runs before each test. It reloads the CLI with mocked plugins.
        """
        import chimera_intel.cli

        # Reload the module to ensure we have the latest code
        reload(chimera_intel.cli)

        # --- FIX: Directly call the factory function ---
        # This ensures the app is created *while the patches are active*,
        # avoiding issues with cached, un-patched module-level variables.
        self.app = chimera_intel.cli.get_cli_app()
        # --- END FIX ---
        
        # This runner is correct for unittest. The mix_stderr comment was a red herring.
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

    # --- FIX: Patch must target the *original source* module ---
    @patch(
        "chimera_intel.core.database.initialize_database", side_effect=ConnectionError("DB Down")
    )
    def test_main_no_db_connection_still_runs_basic_commands(
        self, mock_initialize_database
    ):
        """Tests that the CLI can still run basic commands like --help without a DB connection."""
        # We need to re-run the setup logic with the new, specific patch for this test
        # --- FIX: Patch must target the *original source* module ---
        with patch(
            "chimera_intel.core.plugin_manager.discover_plugins",
            return_value=[MockFootprintPlugin(), MockDefensivePlugin()],
        ):
            import chimera_intel.cli
            reload(chimera_intel.cli)
            app = chimera_intel.cli.get_cli_app()
            runner = CliRunner()
            
            result = runner.invoke(app, ["--help"])
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

    # --- FIX: Remove 'async' keyword from test definition ---
    @patch("chimera_intel.core.footprint.resolve_target", return_value="example.com")
    @patch("chimera_intel.core.footprint.gather_footprint_data", new_callable=AsyncMock)
    @patch("chimera_intel.core.footprint.is_valid_domain", return_value=True)
    def test_scan_footprint_success(self, mock_is_valid: MagicMock, mock_gather_footprint: AsyncMock, mock_resolve_target: MagicMock):
        """Tests a successful 'scan footprint run' command with specific assertions."""
        # Arrange

        mock_result_model = FootprintResult(
            domain="example.com",
            footprint=FootprintData(
                whois_info=WhoisInfo(domain_name="example.com").dict(),
                dns_records={"A": ["127.0.0.1"]},
                subdomains=SubdomainReport(total_unique=0, results=[]),
                ip_threat_intelligence=[
                    ThreatIntelResult(indicator="127.0.0.1", is_malicious=False)
                ],
                historical_dns=HistoricalDns(
                    a_records=["127.0.0.1"], aaaa_records=[], mx_records=[]
                ),
                reverse_ip={"localhost": ["127.0.0.1"]},
                asn_info={"AS12345": AsnInfo(asn="AS12345")},
                tls_cert_info=TlsCertInfo(
                    issuer="Test CA", subject="", sans=[], not_before="", not_after=""
                ),
                dnssec_info=DnssecInfo(
                    dnssec_enabled=False,
                    spf_record="",
                    dmarc_record="",
                ),
                ip_geolocation={
                    "1.1.1.1": IpGeolocation(country="Testland", ip="1.1.1.1")
                },
                cdn_provider=None,
                breach_info=BreachInfo(source="", breaches=[]),
                port_scan_results={"80": PortScanResult(open_ports={})},
                web_technologies=WebTechInfo(),
                personnel_info=PersonnelInfo(employees=[]),
                knowledge_graph=KnowledgeGraph(nodes=[], edges=[]),
            ),
        )
        mock_gather_footprint.return_value = mock_result_model

        # Act

        result = self.runner.invoke(
            self.app, ["scan", "footprint", "run", "example.com"]
        )

        # Assert

        self.assertEqual(result.exit_code, 0, msg=result.output)
        
        # --- FIX for multi-line JSON output ---
        json_output_str = None
        try:
            # Find the start of the JSON object
            start_index = result.stdout.find('{')
            # Find the last closing brace of the main object
            end_index = result.stdout.rfind('}')
            
            if start_index != -1 and end_index != -1 and end_index > start_index:
                json_output_str = result.stdout[start_index : end_index + 1]
                # Try to parse it to make sure it's valid JSON before asserting
                json.loads(json_output_str)
            else:
                json_output_str = None # No valid JSON found
        except json.JSONDecodeError:
            json_output_str = None # Failed to parse
        # --- END FIX ---
        
        self.assertIsNotNone(json_output_str, f"No JSON output found in stdout. Output was: {result.stdout}")
        output = json.loads(json_output_str)
        self.assertEqual(output["domain"], "example.com")
        self.assertIn("footprint", output)

    # --- FIX: Remove 'async' keyword from test definition ---
    @patch("chimera_intel.core.footprint.resolve_target", return_value="invalid-domain")
    @patch("chimera_intel.core.footprint.is_valid_domain", return_value=False) # Mock the internal validation
    def test_scan_footprint_invalid_domain(self, mock_is_valid, mock_resolve_target: MagicMock):
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

        self.assertEqual(result.exit_code, 0, msg=result.output)
        
        json_output_str = None
        try:
            start_index = result.stdout.find('{')
            end_index = result.stdout.rfind('}')
            if start_index != -1 and end_index != -1 and end_index > start_index:
                json_output_str = result.stdout[start_index : end_index + 1]
                # Try to parse it to make sure it's valid JSON before asserting
                json.loads(json_output_str)
            else:
                json_output_str = None
        except json.JSONDecodeError:
            json_output_str = None # Failed to parse, let the assertion fail

        self.assertIsNotNone(json_output_str, f"No JSON output found in stdout. Output was: {result.stdout}")
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
        
        self.assertEqual(result.exit_code, 1)
        self.assertIn("`HIBP_API_KEY` not found in your .env file.", result.stdout)


if __name__ == "__main__":
    unittest.main()