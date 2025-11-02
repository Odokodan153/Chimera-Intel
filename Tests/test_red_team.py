from typer.testing import CliRunner
from unittest.mock import patch
import typer  # Import typer

# Import the application instance and the SWOTAnalysisResult schema
from chimera_intel.core.red_team import simulate_adversary_ttp, red_team_app
from chimera_intel.core.schemas import SWOTAnalysisResult

app = typer.Typer()
app.add_typer(red_team_app)

runner = CliRunner()


def test_generate_scenario_success():
    """
    Tests the successful generation of a red team scenario.
    """
    with (
        patch("chimera_intel.core.red_team.API_KEYS") as mock_api_keys,
        patch(
            "chimera_intel.core.red_team.get_aggregated_data_for_target"
        ) as mock_get_data,
        patch(
            "chimera_intel.core.red_team.generate_swot_from_data"
        ) as mock_generate_swot,
    ):

        # --- Setup Mocks ---

        mock_api_keys.google_api_key = "test_key"
        mock_get_data.return_value = {"vulnerabilities": ["CVE-2023-1234"]}
        mock_generate_swot.return_value = SWOTAnalysisResult(
            analysis_text="Scenario: Phishing campaign targeting employees.", error=None
        )

        # --- Run Command ---
        result = runner.invoke(app, ["red-team", "generate", "TestCorp"])

        # --- Assertions ---

        assert result.exit_code == 0
        assert "Generating potential attack vectors for TestCorp..." in result.stdout
        assert "Red Team Analysis for TestCorp" in result.stdout
        assert "Scenario: Phishing campaign targeting employees." in result.stdout


def test_generate_scenario_no_data():
    """
    Tests the command's behavior when no aggregated data is found for the target.
    """
    with (
        patch("chimera_intel.core.red_team.API_KEYS") as mock_api_keys,
        patch(
            "chimera_intel.core.red_team.get_aggregated_data_for_target"
        ) as mock_get_data,
    ):
        # --- Setup Mocks ---

        mock_api_keys.google_api_key = "test_key"
        mock_get_data.return_value = None  # Simulate no data found

        # --- Run Command ---
        result = runner.invoke(app, ["red-team", "generate", "nonexistent-target"])

        # --- Assertions ---

        assert result.exit_code == 0
        assert "No data found for target 'nonexistent-target'" in result.stdout


def test_generate_scenario_no_api_key():
    """
    Tests that the command fails gracefully if the Google API key is not configured.
    """
    with patch("chimera_intel.core.red_team.API_KEYS") as mock_api_keys:
        # --- Setup Mock ---

        mock_api_keys.google_api_key = None  # Simulate missing API key

        # --- Run Command ---
        result = runner.invoke(app, ["red-team", "generate", "any-target"])

        # --- Assertions ---

        assert result.exit_code == 1
        assert "Error: Google API key not configured." in result.stdout


# --- New Tests for Phishing Simulation ---

def test_phishing_simulation_success():
    """
    Tests successful generation of a phishing simulation.
    """
    with (
        patch("chimera_intel.core.red_team.API_KEYS") as mock_api_keys,
        patch(
            "chimera_intel.core.red_team.get_data_by_module"
        ) as mock_get_data,
        patch(
            "chimera_intel.core.red_team.generate_swot_from_data"
        ) as mock_generate_swot,
    ):
        # --- Setup Mocks ---
        mock_api_keys.google_api_key = "test_key"
        
        # Simulate finding two types of data
        mock_get_data.side_effect = [
            [{"name": "John Doe", "email": "j.doe@example.com"}], # personnel data
            [{"url": "https://portal.example.com/login"}] # content data
        ]
        
        mock_generate_swot.return_value = SWOTAnalysisResult(
            analysis_text="Subject: Urgent Action Required: Portal Login", error=None
        )

        # --- Run Command ---
        result = runner.invoke(app, ["red-team", "phishing-simulation", "TestCorp"])

        # --- Assertions ---
        assert result.exit_code == 0
        assert "Generating phishing simulation for TestCorp..." in result.stdout
        assert "Phishing Simulation Template for TestCorp" in result.stdout
        assert "Subject: Urgent Action Required: Portal Login" in result.stdout
        
        # Check that it tried to get both data types
        assert mock_get_data.call_count == 2
        mock_get_data.assert_any_call("TestCorp", "personnel_osint")
        mock_get_data.assert_any_call("TestCorp", "offensive_enum_content")


def test_phishing_simulation_no_data():
    """
    Tests behavior when no OSINT data is found for the simulation.
    """
    with (
        patch("chimera_intel.core.red_team.API_KEYS") as mock_api_keys,
        patch(
            "chimera_intel.core.red_team.get_data_by_module"
        ) as mock_get_data,
    ):
        # --- Setup Mocks ---
        mock_api_keys.google_api_key = "test_key"
        mock_get_data.return_value = [] # Simulate no data found for either module

        # --- Run Command ---
        result = runner.invoke(app, ["red-team", "phishing-simulation", "NoDataCorp"])

        # --- Assertions ---
        assert result.exit_code == 0
        assert "No OSINT data found for target 'NoDataCorp'" in result.stdout
        assert "Phishing Simulation Template" not in result.stdout

    @patch("chimera_intel.core.red_team.API_KEYS")
    @patch("chimera_intel.core.red_team.get_aggregated_data_for_target")
    @patch("chimera_intel.core.red_team.generate_swot_from_data")
    def test_simulate_adversary_ttp_success(
        self, mock_generate_swot, mock_get_data, mock_api_keys
    ):
        """Tests successful generation of a TTP simulation plan."""
        # Setup Mocks
        mock_api_keys.google_api_key = "fake_key"
        mock_get_data.return_value = {"domains": ["example.com"], "employees": ["test@example.com"]}
        
        mock_ai_response = SWOTAnalysisResult(
            analysis_text="## TTP Objective\nTest simulation plan.",
            error=None
        )
        mock_generate_swot.return_value = mock_ai_response

        # Call the function
        result = simulate_adversary_ttp(target="example.com", ttp_id="T1566")

        # Assertions
        self.assertIsNotNone(result)
        self.assertIn("ttp_simulation_plan", result)
        self.assertEqual(result["ttp_simulation_plan"], "## TTP Objective\nTest simulation plan.")
        mock_get_data.assert_called_with("example.com")
        mock_generate_swot.assert_called_once()

    @patch("chimera_intel.core.red_team.API_KEYS")
    @patch("chimera_intel.core.red_team.get_aggregated_data_for_target")
    def test_simulate_adversary_ttp_no_data(self, mock_get_data, mock_api_keys):
        """Tests simulation when no OSINT data is found."""
        mock_api_keys.google_api_key = "fake_key"
        mock_get_data.return_value = None

        result = simulate_adversary_ttp(target="nodata.com", ttp_id="T1566")

        self.assertIsNone(result)
        mock_get_data.assert_called_with("nodata.com")

    @patch("chimera_intel.core.red_team.API_KEYS")
    def test_simulate_adversary_ttp_no_api_key(self, mock_api_keys):
        """Tests that the function exits if the API key is missing."""
        mock_api_keys.google_api_key = None
        
        with self.assertRaises(typer.Exit) as cm:
            simulate_adversary_ttp(target="example.com", ttp_id="T1566")
        
        self.assertEqual(cm.exception.exit_code, 1)

    @patch("chimera_intel.core.red_team.simulate_adversary_ttp")
    def test_run_ttp_simulation_command(self, mock_simulate_func):
        """Tests the CLI command 'simulate-ttp'."""
        mock_simulate_func.return_value = {"ttp_simulation_plan": "CLI Test Plan"}

        result = self.runner.invoke(
            red_team_app, ["red-team", "simulate-ttp", "example.com", "T1059"]
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("CLI Test Plan", result.stdout)
        self.assertIn("TTP Emulation Plan for example.com (T1059)", result.stdout)
        mock_simulate_func.assert_called_with("example.com", "T1059")
