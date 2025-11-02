"""
Tests for the Reputation Degradation Model.
"""

import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

from chimera_intel.core.reputation_model import (
    _get_amplification_network_strength,
    _project_timeline,
    model_reputation_degradation,
    reputation_app
)

runner = CliRunner()

# --- Fixtures ---

@pytest.fixture
def mock_track_narrative(mocker):
    """Mocks the 'track_narrative' dependency with tiered sources."""
    mock_data = [
        {
            "source": "Reuters", # Tier 1: 25 points
            "type": "News",
            "sentiment": "Neutral"
        },
        {
            "source": "Tweet by User 123", # Tier 5: 1 point
            "type": "Tweet",
            "sentiment": "Negative" # 1.75x bonus
        },
        {
            "source": "Some Local Blog", # Tier 4: 3 points
            "type": "News",
            "sentiment": "Negative" # 1.75x bonus
        },
    ]
    return mocker.patch(
        "chimera_intel.core.reputation_model.track_narrative",
        return_value=mock_data
    )

@pytest.fixture
def mock_synthetic_audit(mocker):
    """Mocks the 'SyntheticMediaAudit' dependency."""
    mock_audit = MagicMock()
    mock_audit.analyze.return_value.confidence = 0.9 # High confidence deepfake
    
    return mocker.patch(
        "chimera_intel.core.reputation_model.SyntheticMediaAudit",
        return_value=mock_audit
    )

# --- Unit Tests ---

def test_get_amplification_network_strength(mock_track_narrative):
    """
    Tests the tiered calculation logic.
    - Reuters (News): 25
    - Tweet (Social): 1 * 1.75 (negative) = 1.75
    - Blog (News): 3 * 1.75 (negative) = 5.25
    - Total: 25 + 1.75 + 5.25 = 32.0
    """
    strength = _get_amplification_network_strength("test query")
    assert strength == 32.0

def test_project_timeline():
    """Tests the ARIMA projection."""
    timeline = _project_timeline(initial_impact=8.0)
    
    assert isinstance(timeline, list)
    assert len(timeline) == 7 # 7-day forecast
    assert all(isinstance(x, float) for x in timeline)
    assert all(0.0 <= x <= 10.0 for x in timeline) # Should be capped
    assert timeline[0] > 0 # Should have a value

# --- Test for Main Function ---

def test_model_reputation_degradation(mock_track_narrative, mock_synthetic_audit):
    """
    Tests the main modeling function.
    - Media Confidence: 0.9 (from mock)
    - Network Strength: 32.0 (from mock)
    - Impact Score = 0.9 * (32.0 / 10.0) = 0.9 * 3.2 = 2.88
    """
    result = model_reputation_degradation("test query", "fake_media.mp4")
    
    assert result.error is None
    assert result.media_synthetic_confidence == 0.9
    assert result.amplification_network_strength == 32.0
    assert result.projected_impact_score == 2.88 # 0.9 * (32.0 / 10)
    assert result.risk_level == "Medium" # 2.0-4.0 range
    assert len(result.projected_impact_timeline) == 7

# --- Test for CLI ---

def test_cli_reputation_model(mock_track_narrative, mock_synthetic_audit):
    """Tests the Typer CLI command."""
    result = runner.invoke(
        reputation_app,
        ["reputation-degradation-model", "test query", "fake_media.mp4"]
    )
    
    assert result.exit_code == 0
    assert "Projected Impact Score:" in result.stdout
    assert "2.88 / 10.0" in result.stdout
    assert "(Medium)" in result.stdout
    assert "Projected 7-Day Impact Timeline" in result.stdout