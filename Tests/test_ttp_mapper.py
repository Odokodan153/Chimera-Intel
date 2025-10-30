from typer.testing import CliRunner
import pytest
from unittest.mock import patch, MagicMock
from chimera_intel.cli import app as main_app
from chimera_intel.core.ttp_mapper import ttp_app, map_cves_to_ttp

# Pydantic models for type checking in logic tests
from chimera_intel.core.schemas import TTPMappingResult, MappedTechnique


main_app.add_typer(ttp_app, name="ttp")

runner = CliRunner()


# --- MOCK DATA FOR LOGIC TESTS ---


@pytest.fixture
def mock_mitre_attack_data():
    """Fixture to mock the MitreAttackData class."""
    with patch("chimera_intel.core.ttp_mapper.MitreAttackData") as mock_class:
        mock_instance = mock_class.return_value

        # Mock technique for CVE-1234
        mock_tech_1 = {
            "name": "Phishing",
            "external_references": [{"external_id": "T1566"}],
            "kill_chain_phases": [
                {"phase_name": "resource-development"},
                {"phase_name": "initial-access"},
            ],
        }

        # Mock technique for CVE-5678 (e.g., has no tactic info)
        mock_tech_2 = {
            "name": "Data Encrypted",
            "external_references": [{"external_id": "T1486"}],
            "kill_chain_phases": [],  # Empty list
        }

        # Configure the mock instance's methods
        def get_techniques_side_effect(cve_id):
            if cve_id == "CVE-2023-1234":
                return [mock_tech_1]
            if cve_id == "CVE-2023-5678":
                return [mock_tech_2]
            if cve_id == "CVE-2023-9999":
                return []  # CVE not found
            if cve_id == "CVE-ERROR":
                raise Exception("MITRE library failure")
            return []

        mock_instance.get_techniques_by_cve_id.side_effect = get_techniques_side_effect
        yield mock_class


# --- CLI TESTS (Original and Extended) ---


@patch("chimera_intel.core.ttp_mapper.save_scan_to_db")
@patch("chimera_intel.core.ttp_mapper.save_or_print_results")
@patch("chimera_intel.core.ttp_mapper.map_cves_to_ttp")
def test_cli_map_cve_success(mock_map_cves, mock_save_print, mock_save_db):
    """Tests the map-cve command with a successful lookup."""
    # Arrange
    mock_results_model = MagicMock()
    mock_results_dict = {
        "total_cves_analyzed": 1,
        "mapped_techniques": [{"cve_id": "CVE-2023-1234"}],
    }
    mock_results_model.model_dump.return_value = mock_results_dict
    mock_map_cves.return_value = mock_results_model

    # Act
    result = runner.invoke(main_app, ["ttp", "map-cve", "CVE-2023-1234"])

    # Assert
    assert result.exit_code == 0, result.output
    mock_map_cves.assert_called_once_with(["CVE-2023-1234"])
    mock_save_print.assert_called_once_with(mock_results_dict, None)
    mock_save_db.assert_called_once_with(
        target="CVE-2023-1234", module="ttp_mapper_cve", data=mock_results_dict
    )


@patch("chimera_intel.core.ttp_mapper.save_scan_to_db")
@patch("chimera_intel.core.ttp_mapper.save_or_print_results")
@patch("chimera_intel.core.ttp_mapper.map_cves_to_ttp")
def test_cli_map_cve_not_found(mock_map_cves, mock_save_print, mock_save_db):
    """Tests the map-cve command when no TTPs are found."""
    # Arrange
    mock_results_model = MagicMock()
    mock_results_dict = {
        "total_cves_analyzed": 1,
        "mapped_techniques": [],
        "error": "Could not map",
    }
    mock_results_model.model_dump.return_value = mock_results_dict
    mock_map_cves.return_value = mock_results_model

    # Act
    result = runner.invoke(main_app, ["ttp", "map-cve", "CVE-INVALID"])

    # Assert
    assert result.exit_code == 0, result.output
    mock_map_cves.assert_called_once_with(["CVE-INVALID"])
    mock_save_print.assert_called_once_with(mock_results_dict, None)
    mock_save_db.assert_called_once()


@patch("chimera_intel.core.ttp_mapper.save_scan_to_db")
@patch("chimera_intel.core.ttp_mapper.save_or_print_results")
@patch("chimera_intel.core.ttp_mapper.map_cves_to_ttp")
def test_cli_map_cve_with_output_file(mock_map_cves, mock_save_print, mock_save_db):
    """Tests the map-cve command with the --output file option."""
    # Arrange
    mock_results_model = MagicMock()
    mock_results_dict = {
        "total_cves_analyzed": 1,
        "mapped_techniques": [{"cve_id": "CVE-2023-1234"}],
    }
    mock_results_model.model_dump.return_value = mock_results_dict
    mock_map_cves.return_value = mock_results_model

    # Act
    result = runner.invoke(
        main_app, ["ttp", "map-cve", "CVE-2023-1234", "--output", "report.json"]
    )

    # Assert
    assert result.exit_code == 0, result.output
    mock_map_cves.assert_called_once_with(["CVE-2023-1234"])
    mock_save_print.assert_called_once_with(mock_results_dict, "report.json")
    mock_save_db.assert_called_once()


@patch("chimera_intel.core.ttp_mapper.save_scan_to_db")
@patch("chimera_intel.core.ttp_mapper.save_or_print_results")
@patch("chimera_intel.core.ttp_mapper.map_cves_to_ttp")
def test_cli_map_cve_multiple_cves(mock_map_cves, mock_save_print, mock_save_db):
    """Tests the CLI command with multiple CVE ID arguments."""
    # Arrange
    mock_results_model = MagicMock()
    mock_results_dict = {"total_cves_analyzed": 2, "mapped_techniques": [{}, {}]}
    mock_results_model.model_dump.return_value = mock_results_dict
    mock_map_cves.return_value = mock_results_model

    # Act
    result = runner.invoke(
        main_app, ["ttp", "map-cve", "CVE-2023-1234", "CVE-2023-5678"]
    )

    # Assert
    assert result.exit_code == 0, result.output
    # Check that map_cves_to_ttp was called with a list
    mock_map_cves.assert_called_once_with(["CVE-2023-1234", "CVE-2023-5678"])
    mock_save_print.assert_called_once_with(mock_results_dict, None)
    # Check that the DB target is a joined string
    mock_save_db.assert_called_once_with(
        target="CVE-2023-1234, CVE-2023-5678",
        module="ttp_mapper_cve",
        data=mock_results_dict,
    )


def test_cli_map_cve_no_cves():
    """Tests the CLI behavior when no CVE IDs are provided.
    Typer should handle this and exit with code 2.
    """
    # Act
    result = runner.invoke(main_app, ["ttp", "map-cve"])  # No CVEs

    # Assert
    assert result.exit_code == 2  # Typer's exit code for missing arguments
    assert "Missing argument" in result.output
    assert "CVE_IDS" in result.output


# --- Unit Tests for 'map_cves_to_ttp' logic ---
# These tests do NOT mock map_cves_to_ttp, but mock the underlying library


def test_logic_map_cves_to_ttp_success(mock_mitre_attack_data):
    """
    Tests the map_cves_to_ttp logic function directly,
    mocking the mitreattack library to confirm parsing.
    """
    # Act
    result = map_cves_to_ttp(["CVE-2023-1234"])

    # Assert
    assert isinstance(result, TTPMappingResult)
    assert result.total_cves_analyzed == 1
    assert result.error is None
    assert len(result.mapped_techniques) == 1

    tech = result.mapped_techniques[0]
    assert isinstance(tech, MappedTechnique)
    assert tech.cve_id == "CVE-2023-1234"
    assert tech.technique_id == "T1566"
    assert tech.technique_name == "Phishing"
    assert tech.tactic == "resource-development, initial-access"

    # Check that the library was initialized
    mock_mitre_attack_data.assert_called_once_with("enterprise-attack.json")


def test_logic_map_cves_to_ttp_parsing_details(mock_mitre_attack_data):
    """
    Tests the logic function's parsing when some data
    (like kill_chain_phases) is missing or empty.
    """
    # Act
    result = map_cves_to_ttp(["CVE-2023-5678"])

    # Assert
    assert result.total_cves_analyzed == 1
    assert result.error is None
    assert len(result.mapped_techniques) == 1

    tech = result.mapped_techniques[0]
    assert tech.cve_id == "CVE-2023-5678"
    assert tech.technique_id == "T1486"
    assert tech.technique_name == "Data Encrypted"
    assert tech.tactic == "N/A"  # Should default to N/A


def test_logic_map_cves_to_ttp_cve_not_found(mock_mitre_attack_data):
    """
    Tests the logic function when a CVE is valid but returns
    no associated techniques from the library.
    """
    # Act
    result = map_cves_to_ttp(["CVE-2023-9999"])

    # Assert
    assert result.total_cves_analyzed == 1
    assert result.error is None
    assert len(result.mapped_techniques) == 0  # No techniques found


def test_logic_map_cves_to_ttp_multiple_cves(mock_mitre_attack_data):
    """
    Tests the logic function with multiple CVEs, one found
    and one not found.
    """
    # Act
    result = map_cves_to_ttp(["CVE-2023-1234", "CVE-2023-9999"])

    # Assert
    assert result.total_cves_analyzed == 2
    assert result.error is None
    assert len(result.mapped_techniques) == 1  # Only one CVE had results
    assert result.mapped_techniques[0].cve_id == "CVE-2023-1234"
    assert result.mapped_techniques[0].technique_id == "T1566"


def test_logic_map_cves_to_ttp_library_exception(mock_mitre_attack_data):
    """
    Tests the logic function's broad 'except Exception' block
    when the mitreattack library itself fails.
    """
    # Act
    result = map_cves_to_ttp(["CVE-ERROR"])

    # Assert
    assert result.total_cves_analyzed == 1
    assert len(result.mapped_techniques) == 0
    assert result.error is not None
    assert "An error occurred: MITRE library failure" in result.error
