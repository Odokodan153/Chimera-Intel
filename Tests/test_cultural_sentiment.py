import pytest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.cultural_sentiment import (
    analyze_regional_sentiment,
    cultural_sentiment_app
)
from chimera_intel.core.schemas import CulturalSentimentResult

runner = CliRunner()

@pytest.fixture
def mock_get_profile():
    """Mocks the get_cultural_profile function."""
    with patch("chimera_intel.core.cultural_sentiment.get_cultural_profile") as mock:
        yield mock

def test_sentiment_direct_culture(mock_get_profile):
    """Tests sentiment in a direct (low-context) culture like 'US'."""
    # Arrange
    mock_get_profile.return_value = {
        "country_code": "US", "directness": 9, "formality": 4
    }
    text = "This is an acceptable solution." # Neutral sentiment
    
    # Act
    result = analyze_regional_sentiment(text, "US")

    # Assert
    assert isinstance(result, CulturalSentimentResult)
    assert result.raw_sentiment == "neutral"
    assert result.interpreted_sentiment == "neutral"
    assert "direct) culture" in result.interpretation
    mock_get_profile.assert_called_with("US")

def test_sentiment_indirect_culture_neutral(mock_get_profile):
    """Tests neutral sentiment in an indirect (high-context) culture like 'JP'."""
    # Arrange
    mock_get_profile.return_value = {
        "country_code": "JP", "directness": 3, "formality": 8
    }
    text = "This is an acceptable solution." # Neutral sentiment
    
    # Act
    result = analyze_regional_sentiment(text, "JP")

    # Assert
    assert isinstance(result, CulturalSentimentResult)
    assert result.raw_sentiment == "neutral"
    assert result.interpreted_sentiment == "potentially_negative"
    assert "high-context" in result.interpretation
    assert "polite disagreement" in result.interpretation
    mock_get_profile.assert_called_with("JP")

def test_sentiment_indirect_culture_negative(mock_get_profile):
    """Tests negative sentiment in an indirect (high-context) culture."""
    # Arrange
    mock_get_profile.return_value = {
        "country_code": "JP", "directness": 3, "formality": 8
    }
    text = "This is terrible." # Negative sentiment
    
    # Act
    result = analyze_regional_sentiment(text, "JP")

    # Assert
    assert isinstance(result, CulturalSentimentResult)
    assert result.raw_sentiment == "negative"
    assert result.interpreted_sentiment == "strongly_negative"
    assert "very strong NEGATIVE" in result.interpretation

def test_sentiment_no_profile(mock_get_profile):
    """Tests fallback when no cultural profile is found."""
    # Arrange
    mock_get_profile.return_value = None
    text = "This is an acceptable solution."
    
    # Act
    result = analyze_regional_sentiment(text, "XX")

    # Assert
    assert isinstance(result, CulturalSentimentResult)
    assert result.raw_sentiment == "neutral"
    assert result.interpreted_sentiment == "neutral"
    assert "No cultural context available" in result.interpretation
    assert result.cultural_profile is None
    mock_get_profile.assert_called_with("XX")

@patch("chimera_intel.core.cultural_sentiment.analyze_regional_sentiment")
@patch("chimera_intel.core.cultural_sentiment.save_or_print_results")
@patch("chimera_intel.core.cultural_sentiment.save_scan_to_db")
def test_cli_cultural_sentiment_run(mock_save_db, mock_save_print, mock_analyze):
    """Tests the 'run' CLI command."""
    # Arrange
    mock_dump_dict = {"text": "test", "interpreted_sentiment": "positive"}
    mock_result = MagicMock(model_dump=lambda exclude_none: mock_dump_dict)
    mock_analyze.return_value = mock_result

    # Act
    result = runner.invoke(cultural_sentiment_app, ["run", "test", "--country", "US"])

    # Assert
    assert result.exit_code == 0
    mock_analyze.assert_called_with("test", "US")
    mock_save_print.assert_called_with(mock_dump_dict, None)
    mock_save_db.assert_called_with(
        target="US_sentiment",
        module="cultural_sentiment",
        data=mock_dump_dict,
    )