import pytest
from typer.testing import CliRunner
import json
from unittest.mock import patch, MagicMock

from chimera_intel.core.multimodal_reasoning import (
    multimodal_reasoning_app,
    run_multimodal_reasoning,
)
from chimera_intel.core.schemas import MultimodalReasoningResult

runner = CliRunner()


@pytest.fixture
def mock_gemini_client():
    with patch(
        "chimera_intel.core.multimodal_reasoning.gemini_client"
    ) as mock_client:
        mock_response = {
            "cross_correlations": [
                "Entity 'Dr. Evil' from 'audio.txt' matches 'Person_1' in 'image.jpg'."
            ],
            "fused_insights": [
                "The 'Volcano Lair' in 'geo.json' is the likely location for the meeting."
            ],
        }
        mock_client.generate_response.return_value = json.dumps(mock_response)
        yield mock_client


def test_run_multimodal_reasoning(mock_gemini_client):
    """Tests the core logic function."""
    inputs = {
        "transcribed_audio": "Dr. Evil mentioned the plan.",
        "image_analysis": "Person_1 in image.jpg resembles Dr. Evil.",
        "geoint_report": "Known location 'Volcano Lair' at 12.34, 56.78",
    }
    result = run_multimodal_reasoning("Dr. Evil", inputs)

    assert isinstance(result, MultimodalReasoningResult)
    assert not result.error
    assert len(result.fused_insights) == 1
    assert "Volcano Lair" in result.fused_insights[0]
    assert len(result.cross_correlations) == 1
    assert "Dr. Evil" in result.cross_correlations[0]


def test_multimodal_reasoning_cli(mock_gemini_client, tmp_path):
    """Tests the CLI command."""
    input_data = {
        "transcribed_audio": "Test audio transcript.",
        "geoint_report": "Test geo report.",
    }
    input_file = tmp_path / "inputs.json"
    input_file.write_text(json.dumps(input_data))

    output_file = tmp_path / "results.json"

    result = runner.invoke(
        multimodal_reasoning_app,
        [
            "run",
            "TestTarget",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    assert output_file.exists()
    
    with open(output_file, "r") as f:
        res_json = json.load(f)
    
    assert res_json["target"] == "TestTarget"
    assert "fused_insights" in res_json
    assert len(res_json["fused_insights"]) == 1

def test_multimodal_reasoning_cli_no_file(mock_gemini_client):
    """Tests CLI error on missing input file."""
    result = runner.invoke(
        multimodal_reasoning_app,
        [
            "run",
            "TestTarget",
            "--input",
            "nonexistentfile.json",
        ],
    )
    assert result.exit_code == 1
    assert "Input file not found" in result.stdout