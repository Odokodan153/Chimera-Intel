import pytest
from typer.testing import CliRunner
import json
from unittest.mock import patch

from chimera_intel.core.event_modeling import (
    event_modeling_app,
    run_event_modeling,
)
from chimera_intel.core.schemas import EventModelingResult

runner = CliRunner()


@pytest.fixture
def mock_gemini_client():
    with patch("chimera_intel.core.event_modeling.gemini_client") as mock_client:
        mock_response = {
            "timeline": [
                {
                    "timestamp": "2024-01-01T10:00:00",
                    "event_description": "First event.",
                    "entities": [{"name": "Entity A", "type": "asset"}],
                    "source_report_hint": "Report 1 says...",
                },
                {
                    "timestamp": "2024-01-01T11:00:00",
                    "event_description": "Second event.",
                    "entities": [{"name": "Entity B", "type": "location"}],
                    "source_report_hint": "Report 2 says...",
                },
            ]
        }
        mock_client.generate_response.return_value = json.dumps(mock_response)
        yield mock_client


def test_run_event_modeling(mock_gemini_client):
    """Tests the core logic function."""
    reports = ["Report 1 says first event at 10am.", "Report 2 says second event at 11am."]
    result = run_event_modeling("TestIncident", reports)

    assert isinstance(result, EventModelingResult)
    assert not result.error
    assert result.total_events == 2
    assert result.timeline[0].event_description == "First event."
    assert result.timeline[1].entities[0].name == "Entity B"


def test_event_modeling_cli(mock_gemini_client, tmp_path):
    """Tests the CLI command."""
    # Create dummy report files
    report1_file = tmp_path / "report1.txt"
    report1_file.write_text("First event happened.")
    
    report2_file = tmp_path / "report2.txt"
    report2_file.write_text("Second event happened.")

    output_file = tmp_path / "timeline.json"

    result = runner.invoke(
        event_modeling_app,
        [
            "run",
            "TestIncident",
            "--input",
            str(tmp_path),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    assert output_file.exists()
    
    with open(output_file, "r") as f:
        res_json = json.load(f)
    
    assert res_json["target"] == "TestIncident"
    assert "timeline" in res_json
    assert len(res_json["timeline"]) == 2
    assert res_json["total_events"] == 2


def test_event_modeling_cli_no_dir(mock_gemini_client):
    """Tests CLI error on missing input directory."""
    result = runner.invoke(
        event_modeling_app,
        [
            "run",
            "TestIncident",
            "--input",
            "nonexistentdir/",
        ],
    )
    assert result.exit_code == 1
    assert "is not a valid directory" in result.stdout