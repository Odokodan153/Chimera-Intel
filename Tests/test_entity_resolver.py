import pytest
import json
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from chimera_intel.core.entity_resolver import entity_app, ResolutionResult
from chimera_intel.core.ai_core import AIAnalysisResult

runner = CliRunner()

@pytest.fixture
def mock_ai_response():
    """Fixture for a successful AI response."""
    response_data = {
        "entities": [
            {"raw_name": "Apex Solutions, LLC", "normalized_name": "Apex Solutions", "entity_type": "company"},
            {"raw_name": "Dr. Jane Doe", "normalized_name": "Jane Doe", "entity_type": "person"}
        ],
        "relationships": [
            {"source_entity": "Jane Doe", "target_entity": "Apex Solutions", "relationship_type": "works_at", "context": "Dr. Jane Doe, founder of Apex Solutions, LLC"}
        ]
    }
    return json.dumps(response_data)

@patch('chimera_intel.core.entity_resolver.API_KEYS.google_api_key', 'fake-api-key')
@patch('chimera_intel.core.entity_resolver.generate_swot_from_data')
def test_resolve_entities_from_text_success(mock_generate_swot, mock_ai_response, tmp_path):
    """Tests the 'resolve-text' command with a successful AI response."""
    
    # Setup mock AI response
    mock_ai_result = AIAnalysisResult(analysis_text=mock_ai_response)
    mock_generate_swot.return_value = mock_ai_result
    
    # Create dummy input file
    input_file = tmp_path / "test_data.txt"
    input_file.write_text("Dr. Jane Doe, founder of Apex Solutions, LLC, is expanding.")
    
    # Create dummy output file path
    output_file = tmp_path / "results.json"

    result = runner.invoke(
        entity_app,
        [
            "resolve-text",
            "Apex Solutions",
            "--input", str(input_file),
            "--output", str(output_file)
        ],
    )

    assert result.exit_code == 0
    assert "Successfully extracted 2 entities and 1 relationships" in result.stdout
    
    # Check that the output file was written correctly
    assert output_file.exists()
    with open(output_file, 'r') as f:
        data = json.load(f)
        assert "entities" in data
        assert "relationships" in data
        assert data["entities"][0]["normalized_name"] == "Apex Solutions"
        assert data["relationships"][0]["relationship_type"] == "works_at"

@patch('chimera_intel.core.entity_resolver.API_KEYS.google_api_key', None)
def test_resolve_text_no_api_key(tmp_path):
    """Tests that the command fails gracefully if no API key is set."""
    input_file = tmp_path / "test_data.txt"
    input_file.write_text("Some text")

    result = runner.invoke(
        entity_app,
        [
            "resolve-text",
            "Target",
            "--input", str(input_file)
        ],
    )
    
    assert result.exit_code == 1
    assert "Error" in result.stdout
    assert "GOOGLE_API_KEY" in result.stdout

def test_resolve_text_no_input_file():
    """Tests that the command fails if the input file is missing."""
    result = runner.invoke(
        entity_app,
        [
            "resolve-text",
            "Target",
            "--input", "nonexistent_file.txt"
        ],
    )
    
    assert result.exit_code == 1
    assert "Error" in result.stdout
    assert "Input file not found" in result.stdout