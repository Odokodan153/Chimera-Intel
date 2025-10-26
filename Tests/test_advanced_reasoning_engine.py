import pytest
import json
from unittest.mock import MagicMock
from chimera_intel.core.advanced_reasoning_engine import (
    decompose_objective,
    generate_reasoning,
)
from chimera_intel.core.schemas import AnalysisResult

# Mock the gemini_client at the module level
@pytest.fixture(autouse=True)
def mock_gemini_client(mocker):
    """Mocks the gemini_client used by the reasoning engine."""
    mock_client = MagicMock()
    # Patch the gemini_client instance in the advanced_reasoning_engine module
    mocker.patch(
        "chimera_intel.core.advanced_reasoning_engine.gemini_client",
        mock_client
    )
    return mock_client

# --- Tests for decompose_objective ---

def test_decompose_objective_success(mock_gemini_client):
    """Tests successful decomposition from a valid LLM JSON response."""
    objective = "Investigate example.com"
    mock_response = '[{"module": "footprint", "params": {"domain": "example.com"}}]'
    mock_gemini_client.generate_response.return_value = mock_response
    
    tasks = decompose_objective(objective)
    
    assert len(tasks) == 1
    assert tasks[0]["module"] == "footprint"
    assert tasks[0]["params"]["domain"] == "example.com"
    mock_gemini_client.generate_response.assert_called_once()

def test_decompose_objective_empty_llm_response_fallback_success(mock_gemini_client, caplog):
    """Tests the regex fallback when LLM returns an empty response."""
    objective = "Analyze the domain evil-corp.com immediately."
    mock_gemini_client.generate_response.return_value = None # Empty response
    
    tasks = decompose_objective(objective)
    
    # Check that it fell back to regex
    assert "LLM call for objective decomposition returned an empty response" in caplog.text
    assert "Using dynamic fallback, starting with footprint for: evil-corp.com" in caplog.text
    
    # Check that the task was created correctly
    assert len(tasks) == 1
    assert tasks[0]["module"] == "footprint"
    assert tasks[0]["params"]["domain"] == "evil-corp.com"

def test_decompose_objective_empty_llm_response_fallback_fail(mock_gemini_client, caplog):
    """Tests the fallback when LLM is empty and regex finds no domain."""
    objective = "Analyze the threat actor 'Wizard Spider'"
    mock_gemini_client.generate_response.return_value = None # Empty response
    
    tasks = decompose_objective(objective)
    
    assert "LLM call for objective decomposition returned an empty response" in caplog.text
    assert "Using dynamic fallback" not in caplog.text # Regex fails
    assert len(tasks) == 0 # Returns empty list

def test_decompose_objective_json_decode_error(mock_gemini_client, caplog):
    """Tests handling of a malformed JSON response from the LLM."""
    objective = "Investigate example.com"
    mock_response = '[{"module": "footprint", "params": ...' # Invalid JSON
    mock_gemini_client.generate_response.return_value = mock_response
    
    tasks = decompose_objective(objective)
    
    assert "Failed to parse LLM JSON response for decomposition" in caplog.text
    assert len(tasks) == 0

def test_decompose_objective_invalid_structure(mock_gemini_client, caplog):
    """Tests handling of valid JSON that doesn't match the expected structure."""
    objective = "Investigate example.com"
    # Valid JSON, but wrong structure (missing 'params')
    mock_response = '[{"module": "footprint"}]'
    mock_gemini_client.generate_response.return_value = mock_response
    
    tasks = decompose_objective(objective)
    
    assert "LLM output is not in the expected format" in caplog.text
    assert len(tasks) == 0
    
    # Test with another invalid structure (not a list)
    mock_response = '{"module": "footprint", "params": {"domain": "example.com"}}'
    mock_gemini_client.generate_response.return_value = mock_response
    
    tasks = decompose_objective(objective)
    assert "LLM output is not in the expected format" in caplog.text
    assert len(tasks) == 0


# --- Tests for generate_reasoning ---

@pytest.fixture
def mock_pydantic_data():
    """Mock for a Pydantic-like object with a .dict() method."""
    mock_data = MagicMock()
    mock_data.dict.return_value = {"pydantic_key": "pydantic_value"}
    return mock_data

def test_generate_reasoning_success(mock_gemini_client, mock_pydantic_data):
    """Tests successful reasoning from a valid LLM JSON response."""
    objective = "Analyze example.com"
    # Test serialization of different data types
    results = [
        AnalysisResult(module_name="footprint", data={"key": "value"}),
        AnalysisResult(module_name="threat_intel", data=["ioc1", "ioc2"]),
        AnalysisResult(module_name="pydantic_mod", data=mock_pydantic_data),
        AnalysisResult(module_name="string_mod", data="This is a simple string result"),
    ]
    
    mock_json_response = {
        "hypotheses": ["Hypothesis 1"],
        "recommendations": ["Recommendation 1"],
        "next_steps": [{"module": "vulnerability_scanner", "params": {"host": "1.2.3.4"}}],
        "analytical_summary": "Summary text."
    }
    mock_gemini_client.generate_response.return_value = json.dumps(mock_json_response)
    
    output = generate_reasoning(objective, results)
    
    # Check that the prompt contains all serialized data
    prompt_arg = mock_gemini_client.generate_response.call_args[0][0]
    assert '"module": "footprint"' in prompt_arg
    assert '"key": "value"' in prompt_arg
    assert '"module": "threat_intel"' in prompt_arg
    assert '"ioc1"' in prompt_arg
    assert '"module": "pydantic_mod"' in prompt_arg
    assert '"pydantic_key": "pydantic_value"' in prompt_arg
    assert '"module": "string_mod"' in prompt_arg
    assert 'This is a simple string result' in prompt_arg
    
    # Check that the output is parsed correctly
    assert output.hypotheses == ["Hypothesis 1"]
    assert output.recommendations == ["Recommendation 1"]
    assert output.analytical_summary == "Summary text."
    assert len(output.next_steps) == 1
    assert output.next_steps[0]["module"] == "vulnerability_scanner"

def test_generate_reasoning_empty_llm_response(mock_gemini_client, caplog):
    """Tests the fallback when the LLM returns an empty response."""
    mock_gemini_client.generate_response.return_value = None
    
    output = generate_reasoning("Test", [])
    
    assert "LLM call for reasoning returned an empty response" in caplog.text
    assert output.analytical_summary == "Reasoning failed: no response from LLM."
    assert output.hypotheses == []
    assert output.next_steps == []

def test_generate_reasoning_json_decode_error(mock_gemini_client, caplog):
    """Tests handling of malformed JSON from the reasoning LLM."""
    mock_gemini_client.generate_response.return_value = '{"hypotheses": ...' # Invalid JSON
    
    output = generate_reasoning("Test", [])
    
    assert "Failed to parse LLM JSON response for reasoning" in caplog.text
    assert output.analytical_summary == "Reasoning failed due to malformed LLM response."
    assert output.hypotheses == []

def test_generate_reasoning_footprint_guard_rail(mock_gemini_client):
    """Tests that the 'footprint' module is filtered from next_steps."""
    objective = "Analyze example.com"
    # Results include 'footprint', which should trigger the guard
    results = [AnalysisResult(module_name="footprint", data={"domain": "example.com"})]
    
    mock_json_response = {
        "hypotheses": [],
        "recommendations": [],
        "next_steps": [
            {"module": "footprint", "params": {"domain": "example.com"}}, # Should be filtered
            {"module": "threat_intel", "params": {"indicator": "example.com"}} # Should remain
        ],
        "analytical_summary": "Summary."
    }
    mock_gemini_client.generate_response.return_value = json.dumps(mock_json_response)
    
    output = generate_reasoning(objective, results)
    
    # Check that the footprint task was removed
    assert len(output.next_steps) == 1
    assert output.next_steps[0]["module"] == "threat_intel"

def test_generate_reasoning_footprint_guard_rail_not_triggered(mock_gemini_client):
    """Tests that the guard rail is NOT triggered if 'footprint' is not in results."""
    objective = "Analyze example.com"
    # Results do NOT include 'footprint'
    results = [AnalysisResult(module_name="threat_intel", data={"indicator": "example.com"})]
    
    mock_json_response = {
        "hypotheses": [],
        "recommendations": [],
        "next_steps": [
            {"module": "footprint", "params": {"domain": "example.com"}}, # Should remain
            {"module": "threat_intel", "params": {"indicator": "example.com"}} # Should remain
        ],
        "analytical_summary": "Summary."
    }
    mock_gemini_client.generate_response.return_value = json.dumps(mock_json_response)
    
    output = generate_reasoning(objective, results)
    
    # Check that NO tasks were removed
    assert len(output.next_steps) == 2
    assert output.next_steps[0]["module"] == "footprint"