import pytest
import json
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, ANY

from chimera_intel.core.covert_intel_agent import covert_app
from chimera_intel.core.ai_core import AIResult

runner = CliRunner()

# --- Patch the real import paths of the dependent functions ---
@patch("chimera_intel.core.covert_intel_agent.search_personnel")
@patch("chimera_intel.core.covert_intel_agent.search_company")
@patch("chimera_intel.core.covert_intel_agent.analyze_footprint")
@patch("chimera_intel.core.covert_intel_agent.track_narrative")
@patch("chimera_intel.core.covert_intel_agent.generate_swot_from_data")
def test_run_investigation(mock_ai, mock_track, mock_analyze, mock_company, mock_person):
    """
    Tests the full multi-step investigation flow by patching the
    functions imported from other modules.
    """
    # 1. Define the AI-generated plan
    mock_plan = [
        {"module": "person_intel", "query": "John Doe"},
        {"module": "company_intel", "query": "Acme Corp"},
        {"module": "digital_footprint", "query": "acme.com"},
        {"module": "narrative_analysis", "query": "Acme Corp influence"}
    ]
    mock_plan_json = json.dumps(mock_plan)
    mock_ai.return_value = AIResult(analysis_text=mock_plan_json, error=None)

    # 2. Define the return values for the mock modules
    mock_person.return_value = {"name": "John Doe", "linked_companies": ["Acme Corp"]}
    mock_company.return_value = {"company": "Acme Corp", "assets": ["acme.com"]}
    mock_analyze.return_value = {"domain": "acme.com", "summary": "Active on forums"}
    mock_track.return_value = [{"source": "News", "content": "Acme Corp is great"}]

    # 3. Run the command
    result = runner.invoke(
        covert_app,
        ["run", "--target", "John Doe", "--objective", "Find assets and influence"],
        input="John Doe\nFind assets and influence\n" # Handle prompts
    )

    # 4. Assert results
    assert result.exit_code == 0
    assert "Generating investigation plan" in result.stdout
    assert "EXECUTING INVESTIGATION PLAN" in result.stdout
    
    # Check that the AI was called correctly
    mock_ai.assert_called_once_with(ANY, ANY)
    assert "Objective: Find assets and influence" in mock_ai.call_args[0][0]

    # Check that the plan steps were executed in order
    mock_person.assert_called_once_with("John Doe")
    mock_company.assert_called_once_with("Acme Corp")
    mock_analyze.assert_called_once_with("acme.com")
    mock_track.assert_called_once_with("Acme Corp influence")

    assert "INVESTIGATION COMPLETE" in result.stdout
    assert "Final Report Summary" in result.stdout
    assert "investigation_report_John_Doe.json" in result.stdout

@patch("chimera_intel.core.covert_intel_agent.generate_swot_from_data")
def test_run_investigation_ai_error(mock_ai):
    """
    Tests failure if the AI plan generation fails.
    """
    mock_ai.return_value = AIResult(analysis_text=None, error="AI failed")

    result = runner.invoke(
        covert_app,
        ["run", "--target", "Test", "--objective", "Test"],
        input="Test\nTest\n"
    )
    
    assert result.exit_code == 1
    assert "AI Error: AI failed" in result.stdout