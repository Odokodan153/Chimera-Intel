"""
Tests for the Disinformation Analyzer module.
"""

import pytest
from typer.testing import CliRunner
from unittest.mock import patch

from chimera_intel.core.disinformation_analyzer import (
    analyze_text_for_synthesis,
    map_synthetic_narrative,
    disinformation_app
)

runner = CliRunner()

# --- Test Data ---

TEXT_AI_PHRASE = "As an AI language model, I cannot provide personal opinions. The situation is complex."

TEXT_UNIFORM_AI = (
    "The new policy is a significant development. It will impact many people. "
    "We must consider all the angles. The future will be challenging. "
    "This is a very important time for us. We need to work together."
) # Low TTR, very low sentence length variance

TEXT_HUMAN = (
    "Wow, this new policy is just nuts! I mean, seriously? "
    "They're going to impact *everyone* and they clearly didn't think it through. "
    "What a mess. What are we supposed to do now?"
) # High TTR, high variance

# --- Unit Tests for Heuristics ---

def test_analyze_text_for_synthesis_ai_phrase():
    """Tests the high-confidence 'smoking gun' AI phrase."""
    result = analyze_text_for_synthesis(TEXT_AI_PHRASE)
    assert result.is_synthetic is True
    assert result.confidence > 0.9
    assert "disclaimer phrase" in result.evidence

def test_analyze_text_for_synthesis_uniform_ai():
    """Tests the statistical heuristic for uniform AI text."""
    result = analyze_text_for_synthesis(TEXT_UNIFORM_AI)
    assert result.is_synthetic is True
    assert result.confidence > 0.6 # 0.6 is the threshold
    assert "High uniformity" in result.evidence

def test_analyze_text_for_synthesis_human():
    """Tests that 'bursty' human text is correctly identified as non-synthetic."""
    result = analyze_text_for_synthesis(TEXT_HUMAN)
    assert result.is_synthetic is False
    assert result.confidence == 0.0

# --- Test for Main Function ---

@pytest.fixture
def mock_track_narrative(mocker):
    """Mocks the 'track_narrative' dependency."""
    mock_data = [
        {
            "source": "Tweet by User 123",
            "type": "Tweet",
            "content": TEXT_UNIFORM_AI,
            "sentiment": "Negative"
        },
        {
            "source": "LocalBlog.com",
            "type": "News",
            "content": TEXT_HUMAN,
            "sentiment": "Negative"
        },
        {
            "source": "Tweet by Bot 456",
            "type": "Tweet",
            "content": TEXT_AI_PHRASE,
            "sentiment": "Neutral"
        }
    ]
    return mocker.patch(
        "chimera_intel.core.disinformation_analyzer.track_narrative",
        return_value=mock_data
    )

def test_map_synthetic_narrative(mock_track_narrative):
    """Tests the main mapping function."""
    result = map_synthetic_narrative("test query")

    assert result.error is None
    assert result.total_items_found == 3
    assert result.synthetic_items_detected == 2
    assert result.synthetic_items_by_type == {"Tweet": 2}
    
    # Check that the human-written news article was excluded
    assert len(result.synthetic_narrative_map) == 2
    assert result.synthetic_narrative_map[0].content == TEXT_UNIFORM_AI
    assert result.synthetic_narrative_map[1].content == TEXT_AI_PHRASE

# --- Test for CLI ---

def test_cli_synthetic_narrative_map(mock_track_narrative):
    """Tests the Typer CLI command."""
    result = runner.invoke(disinformation_app, ["synthetic-narrative-map", "test query"])
    
    assert result.exit_code == 0
    assert "Mapping synthetic narrative for" in result.stdout
    assert "Detected 2 suspected synthetic items" in result.stdout
    assert "'Tweet': 2" in result.stdout