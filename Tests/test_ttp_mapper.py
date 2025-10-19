from typer.testing import CliRunner
from unittest.mock import patch, ANY
from pydantic import BaseModel

# ---: Import the MAIN app and the app to be tested ---

from chimera_intel.cli import app as main_app
from chimera_intel.core.ttp_mapper import ttp_app

# --- : Manually register the app as a plugin ---
# This simulates the plugin discovery from cli.py

main_app.add_typer(ttp_app, name="ttp")

runner = CliRunner()


# Mock Pydantic model for return value


class MockResultsModel(BaseModel):
    cve_id: str
    techniques: list

    def model_dump_json(self, *args, **kwargs):
        return '{"cve_id": "CVE-2023-1234", "techniques": []}'


@patch("chimera_intel.core.ttp_mapper.map_cves_to_ttp")
def test_cli_map_cve_success(mock_map_cves, mocker):
    """Tests the map-cve command with a successful lookup."""
    mock_console_print = mocker.patch("chimera_intel.core.ttp_mapper.console.print")
    mock_map_cves.return_value = MockResultsModel(cve_id="CVE-2023-1234", techniques=[])

    # ---: Invoke the main_app with the full command ---

    result = runner.invoke(main_app, ["ttp", "map-cve", "CVE-2023-1234"])

    assert result.exit_code == 0
    mock_map_cves.assert_called_once_with(["CVE-2023-1234"])
    # Check that the Rich Panel was printed

    mock_console_print.assert_any_call(ANY)


@patch("chimera_intel.core.ttp_mapper.map_cves_to_ttp")
def test_cli_map_cve_not_found(mock_map_cves, mocker):
    """Tests the map-cve command when no TTPs are found."""
    mock_console_print = mocker.patch("chimera_intel.core.ttp_mapper.console.print")
    mock_map_cves.return_value = None  # Simulate failure to find CVE

    # ---: Invoke the main_app with the full command ---

    result = runner.invoke(main_app, ["ttp", "map-cve", "CVE-INVALID"])

    # ---: Check for the correct failure exit code ---

    assert result.exit_code == 1
    mock_map_cves.assert_called_once_with(["CVE-INVALID"])
    mock_console_print.assert_any_call(
        "[bold red]Could not map TTPs for the provided CVEs.[/bold red]"
    )


@patch("chimera_intel.core.ttp_mapper.save_results_to_file")
@patch("chimera_intel.core.ttp_mapper.map_cves_to_ttp")
def test_cli_map_cve_with_output_file(mock_map_cves, mock_save_results, mocker):
    """Tests the map-cve command with the --output file option."""
    mock_console_print = mocker.patch("chimera_intel.core.ttp_mapper.console.print")
    mock_results = MockResultsModel(cve_id="CVE-2023-1234", techniques=[])
    mock_map_cves.return_value = mock_results

    result = runner.invoke(
        main_app, ["ttp", "map-cve", "CVE-2023-1234", "--output", "report.json"]
    )

    assert result.exit_code == 0
    # Check that the save function was called with the correct args

    mock_save_results.assert_called_once_with(mock_results, "report.json")
    mock_console_print.assert_any_call(
        "[green]TTP mapping results saved to report.json[/green]"
    )
