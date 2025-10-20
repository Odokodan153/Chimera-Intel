from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# ---: Import the MAIN app and the app to be tested ---

from chimera_intel.cli import app as main_app
from chimera_intel.core.ttp_mapper import ttp_app

main_app.add_typer(ttp_app, name="ttp")

runner = CliRunner()


# Mock the return from map_cves_to_ttp


@patch("chimera_intel.core.ttp_mapper.save_scan_to_db")
@patch(
    "chimera_intel.core.ttp_mapper.save_or_print_results"
)  
@patch("chimera_intel.core.ttp_mapper.map_cves_to_ttp")
def test_cli_map_cve_success(mock_map_cves, mock_save_print, mock_save_db):
    """Tests the map-cve command with a successful lookup."""
    # This mock is what map_cves_to_ttp returns

    mock_results_model = MagicMock()
    mock_results_dict = {
        "total_cves_analyzed": 1,
        "mapped_techniques": [{"cve_id": "CVE-2023-1234"}],
    }
    mock_results_model.model_dump.return_value = mock_results_dict
    mock_map_cves.return_value = mock_results_model

    result = runner.invoke(main_app, ["ttp", "map-cve", "CVE-2023-1234"])

    assert result.exit_code == 0, result.output
    mock_map_cves.assert_called_once_with(["CVE-2023-1234"])
    # Check that the utility function was called correctly

    mock_save_print.assert_called_once_with(mock_results_dict, None)
    mock_save_db.assert_called_once_with(
        target="CVE-2023-1234", module="ttp_mapper_cve", data=mock_results_dict
    )


@patch("chimera_intel.core.ttp_mapper.save_scan_to_db")
@patch(
    "chimera_intel.core.ttp_mapper.save_or_print_results"
) 
@patch("chimera_intel.core.ttp_mapper.map_cves_to_ttp")
def test_cli_map_cve_not_found(mock_map_cves, mock_save_print, mock_save_db):
    """Tests the map-cve command when no TTPs are found."""
    # The command still succeeds, it just returns an empty/error result

    mock_results_model = MagicMock()
    mock_results_dict = {
        "total_cves_analyzed": 1,
        "mapped_techniques": [],
        "error": "Could not map",
    }
    mock_results_model.model_dump.return_value = mock_results_dict
    mock_map_cves.return_value = mock_results_model

    result = runner.invoke(main_app, ["ttp", "map-cve", "CVE-INVALID"])

    assert result.exit_code == 0, result.output
    mock_map_cves.assert_called_once_with(["CVE-INVALID"])
    # Check that the utility function was called with the empty/error result

    mock_save_print.assert_called_once_with(mock_results_dict, None)
    mock_save_db.assert_called_once()


@patch("chimera_intel.core.ttp_mapper.save_scan_to_db")
@patch(
    "chimera_intel.core.ttp_mapper.save_or_print_results"
)  # FIX: Patch the correct util function
@patch("chimera_intel.core.ttp_mapper.map_cves_to_ttp")
def test_cli_map_cve_with_output_file(mock_map_cves, mock_save_print, mock_save_db):
    """Tests the map-cve command with the --output file option."""
    mock_results_model = MagicMock()
    mock_results_dict = {
        "total_cves_analyzed": 1,
        "mapped_techniques": [{"cve_id": "CVE-2023-1234"}],
    }
    mock_results_model.model_dump.return_value = mock_results_dict
    mock_map_cves.return_value = mock_results_model

    result = runner.invoke(
        main_app, ["ttp", "map-cve", "CVE-2023-1234", "--output", "report.json"]
    )

    assert result.exit_code == 0, result.output
    # Check that the save function was called with the correct args

    mock_save_print.assert_called_once_with(mock_results_dict, "report.json")
    mock_save_db.assert_called_once()
