from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import pytest
import json
from unittest.mock import patch, MagicMock
from chimera_intel.core.ttp_mapper import TTP, MappedTTP, TTPMapper
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

@pytest.fixture
def mock_ttp_data():
    """Mock TTP data for testing."""
    return [
        {
            "id": "T1566",
            "name": "Phishing",
            "description": "Adversaries may send phishing messages...",
            "examples": ["Spearphishing Link", "Spearphishing Attachment"],
        },
        {
            "id": "T1078",
            "name": "Valid Accounts",
            "description": "Adversaries may obtain and abuse credentials...",
            "examples": ["Default Accounts", "Local Accounts"],
        },
    ]


@pytest.fixture
def mock_ttp_file(tmp_path, mock_ttp_data):
    """Creates a temporary TTP JSON file."""
    ttp_file = tmp_path / "ttps.json"
    with open(ttp_file, "w") as f:
        json.dump(mock_ttp_data, f)
    return str(ttp_file)


# --- Original Tests (for context, mostly unchanged) ---

def test_ttp_model():
    """Tests the TTP pydantic model."""
    data = {
        "id": "T1000",
        "name": "Test Tactic",
        "description": "A test TTP.",
        "examples": ["Example 1"],
    }
    ttp = TTP(**data)
    assert ttp.id == "T1000"
    assert ttp.name == "Test Tactic"


def test_mapped_ttp_model():
    """Tests the MappedTTP pydantic model."""
    ttp_data = {
        "id": "T1000",
        "name": "Test Tactic",
        "description": "A test TTP.",
        "examples": ["Example 1"],
    }
    ttp = TTP(**ttp_data)
    mapped_ttp = MappedTTP(
        ttp=ttp, confidence=0.9, rationale="High confidence match."
    )
    assert mapped_ttp.confidence == 0.9
    assert mapped_ttp.ttp.id == "T1000"


def test_ttp_mapper_init_success(mock_ttp_file):
    """Tests successful initialization of TTPMapper."""
    mapper = TTPMapper(ttp_definition_file=mock_ttp_file)
    assert len(mapper.ttp_list) == 2
    assert "T1566" in mapper.ttps
    assert mapper.ttps["T1566"].name == "Phishing"


def test_ttp_mapper_init_file_not_found():
    """Tests TTPMapper init with a non-existent file."""
    with pytest.raises(FileNotFoundError):
        TTPMapper(ttp_definition_file="non_existent.json")


def test_ttp_mapper_init_json_decode_error(tmp_path):
    """Tests TTPMapper init with a corrupt JSON file."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{invalid json,")
    
    with pytest.raises(json.JSONDecodeError):
        TTPMapper(ttp_definition_file=str(bad_file))


def test_get_ttp_by_id(mock_ttp_file):
    """Tests the get_ttp_by_id method."""
    mapper = TTPMapper(ttp_definition_file=mock_ttp_file)
    
    ttp = mapper.get_ttp_by_id("T1566")
    assert ttp is not None
    assert ttp.name == "Phishing"
    
    ttp_none = mapper.get_ttp_by_id("T9999")
    assert ttp_none is None


def test_search_ttps(mock_ttp_file):
    """Tests the search_ttps method."""
    mapper = TTPMapper(ttp_definition_file=mock_ttp_file)
    
    results = mapper.search_ttps("phishing")
    assert len(results) == 1
    assert results[0].id == "T1566"
    
    results_desc = mapper.search_ttps("credentials")
    assert len(results_desc) == 1
    assert results_desc[0].id == "T1078"

    results_none = mapper.search_ttps("nomatch")
    assert len(results_none) == 0


# --- NEW AND EXTENDED TESTS ---

@pytest.fixture
def mock_invalid_ttp_file(tmp_path):
    """Creates a temporary TTP JSON file with one valid and one invalid TTP."""
    # T1566 is valid, T1078 is invalid (missing 'name')
    invalid_data = [
        {
            "id": "T1566",
            "name": "Phishing",
            "description": "Adversaries may send phishing messages...",
            "examples": ["Spearphishing Link"],
        },
        {
            "id": "T1078",
            "description": "Adversaries may obtain and abuse credentials...",
            "examples": ["Default Accounts"],
        },
    ]
    ttp_file = tmp_path / "invalid_ttps.json"
    with open(ttp_file, "w") as f:
        json.dump(invalid_data, f)
    return str(ttp_file)


def test_ttp_mapper_init_invalid_ttp_data(mock_invalid_ttp_file):
    """
    Tests that the mapper logs an error but still loads valid TTPs
    when encountering invalid data in the JSON file.
    """
    # We expect a Pydantic ValidationError to be caught and logged
    with patch("chimera_intel.core.ttp_mapper.logger.error") as mock_logger:
        mapper = TTPMapper(ttp_definition_file=mock_invalid_ttp_file)
        
        # The valid TTP should be loaded
        assert len(mapper.ttp_list) == 1
        assert "T1566" in mapper.ttps
        
        # The invalid TTP should NOT be loaded
        assert "T1078" not in mapper.ttps
        
        # Check that an error was logged for the invalid entry
        mock_logger.assert_called_once()
        assert "Failed to validate TTP data" in mock_logger.call_args[0][0]


def test_create_prompt(mock_ttp_file):
    """Tests the internal _create_prompt method."""
    mapper = TTPMapper(ttp_definition_file=mock_ttp_file)
    input_text = "User clicked a link."
    prompt = mapper._create_prompt(input_text)
    
    assert input_text in prompt
    assert "T1566" in prompt
    assert "Phishing" in prompt
    assert "T1078" in prompt
    assert "Valid Accounts" in prompt
    assert "Your task is to analyze" in prompt
    assert "JSON array of objects" in prompt


@pytest.fixture
def mapper_for_parsing(mock_ttp_file):
    """Provides a TTPMapper instance for use in parser tests."""
    return TTPMapper(ttp_definition_file=mock_ttp_file)


def test_parse_llm_response_success(mapper_for_parsing):
    """Tests the _parse_llm_response method with a valid response."""
    llm_json_response = json.dumps([
        {"id": "T1566", "confidence": 0.9, "rationale": "Text mentions 'clicked a link'."},
        {"id": "T1078", "confidence": 0.2, "rationale": "Low confidence."}
    ])
    
    results = mapper_for_parsing._parse_llm_response(llm_json_response, min_confidence=0.5)
    
    assert len(results) == 1
    assert results[0].ttp.id == "T1566"
    assert results[0].confidence == 0.9
    assert results[0].rationale == "Text mentions 'clicked a link'."


def test_parse_llm_response_invalid_json(mapper_for_parsing):
    """Tests the _parse_llm_response method with corrupt JSON."""
    llm_bad_response = "[{'id': 'T1566'}" # Invalid JSON
    
    with patch("chimera_intel.core.ttp_mapper.logger.error") as mock_logger:
        results = mapper_for_parsing._parse_llm_response(llm_bad_response)
        assert len(results) == 0
        mock_logger.assert_called_once()
        assert "Failed to decode LLM response as JSON" in mock_logger.call_args[0][0]


def test_parse_llm_response_wrong_schema(mapper_for_parsing):
    """Tests the _parse_llm_response method with valid JSON but wrong data structure."""
    # Missing 'confidence'
    llm_wrong_schema = json.dumps([
        {"id": "T1566", "rationale": "Forgot confidence."}
    ])
    
    with patch("chimera_intel.core.ttp_mapper.logger.warning") as mock_logger:
        results = mapper_for_parsing._parse_llm_response(llm_wrong_schema)
        assert len(results) == 0
        mock_logger.assert_called_once()
        assert "Failed to validate mapped TTP" in mock_logger.call_args[0][0]


def test_parse_llm_response_unknown_ttp_id(mapper_for_parsing):
    """Tests the _parse_llm_response method with a TTP ID that doesn't exist."""
    llm_unknown_id = json.dumps([
        {"id": "T9999", "confidence": 0.8, "rationale": "Made this TTP up."}
    ])
    
    with patch("chimera_intel.core.ttp_mapper.logger.warning") as mock_logger:
        results = mapper_for_parsing._parse_llm_response(llm_unknown_id)
        assert len(results) == 0
        mock_logger.assert_called_once()
        assert "LLM returned unknown TTP ID 'T9999'" in mock_logger.call_args[0][0]


@patch("chimera_intel.core.llm_interface.LLMClient")
def test_map_text_to_ttps_integration_success(MockLLMClient, mock_ttp_file):
    """
    Tests map_text_to_ttps as an integration test.
    Mocks only the LLM client's response, allowing _parse_llm_response to be tested.
    """
    # Arrange
    mock_llm_instance = MockLLMClient.return_value
    llm_json_response = json.dumps([
        {"id": "T1566", "confidence": 0.9, "rationale": "Text mentions 'clicked a link'."},
        {"id": "T1078", "confidence": 0.3, "rationale": "Low confidence."}
    ])
    mock_llm_instance.generate_response.return_value = llm_json_response
    
    mapper = TTPMapper(ttp_definition_file=mock_ttp_file)
    input_text = "The user clicked a suspicious link in an email."
    
    # Act
    results = mapper.map_text_to_ttps(input_text, mock_llm_instance, min_confidence=0.5)
    
    # Assert
    mock_llm_instance.generate_response.assert_called_once()
    assert len(results) == 1
    assert results[0].ttp.id == "T1566"
    assert results[0].confidence == 0.9


@patch("chimera_intel.core.llm_interface.LLMClient")
def test_map_text_to_ttps_llm_exception(MockLLMClient, mock_ttp_file):
    """Tests map_text_to_ttps when the LLM client raises an exception."""
    # Arrange
    mock_llm_instance = MockLLMClient.return_value
    mock_llm_instance.generate_response.side_effect = Exception("LLM API is down")
    
    mapper = TTPMapper(ttp_definition_file=mock_ttp_file)
    input_text = "Some text"
    
    # Act & Assert
    with patch("chimera_intel.core.ttp_mapper.logger.error") as mock_logger:
        results = mapper.map_text_to_ttps(input_text, mock_llm_instance)
        assert len(results) == 0
        mock_logger.assert_called_once()
        assert "LLM client failed to generate TTP mapping" in mock_logger.call_args[0][0]