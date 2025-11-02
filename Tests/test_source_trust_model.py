import pytest
from typer.testing import CliRunner
import json
from unittest.mock import patch

from chimera_intel.core.source_trust_model import source_trust_model_app

runner = CliRunner()


@patch("chimera_intel.core.source_trust_model.save_scan_to_db")
def test_run_source_trust_cli_fringe(mock_save):
    """Tests that a fringe source gets a low score."""
    result = runner.invoke(
        source_trust_model_app,
        ["run", "my-fringe-forum.net", "--type", "fringe_forum"],
    )
    assert result.exit_code == 0
    # Use starts_with for JSON check as the exact score is hashed
    assert '"trust_score": 0.' in result.stdout
    assert '"source_type_guess": "Unverified Fringe Forum"' in result.stdout
    
    output_json = json.loads(result.stdout)
    assert output_json["trust_score"] < 0.3


@patch("chimera_intel.core.source_trust_model.save_scan_to_db")
def test_run_source_trust_cli_gov(mock_save):
    """Tests that a gov source gets a high score."""
    result = runner.invoke(
        source_trust_model_app,
        ["run", "sec.gov"],
    )
    assert result.exit_code == 0
    
    output_json = json.loads(result.stdout)
    assert output_json["trust_score"] > 0.85
    assert output_json["source_type_guess"] == "Verified Government Registry"