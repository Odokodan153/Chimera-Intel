import pytest
from unittest.mock import MagicMock
from chimera_intel.core.cognitive_warfare_engine import CognitiveWarfareEngine
from chimera_intel.core.schemas import TwitterMonitoringResult, Tweet


@pytest.fixture
def mock_cwe_dependencies(mocker):
    """Mocks the dependencies of the CognitiveWarfareEngine to prevent Typer exits and real API calls."""
    # Mock the narrative analyzer which is a Typer command
    mocker.patch(
        "chimera_intel.core.cognitive_warfare_engine.track_narrative",
        return_value=[{"content": "A positive story", "source": "Web/News", "sentiment": "Positive"}]
    )

    # Mock the social media monitor to prevent real network calls
    mock_twitter_result = TwitterMonitoringResult(
        query="test",
        total_tweets_found=1,
        tweets=[Tweet(id="1", text="A negative tweet", author_id="123", created_at="2023-01-01T12:00:00Z")]
    )
    mocker.patch(
        "chimera_intel.core.cognitive_warfare_engine.monitor_twitter_stream",
        return_value=mock_twitter_result
    )


def test_cognitive_warfare_engine_initialization(mock_cwe_dependencies):
    """
    Tests that the CognitiveWarfareEngine initializes correctly with mocked dependencies.
    """
    # --- Act ---
    # Initialize the engine. The mocked functions will be called instead of the real ones.
    engine = CognitiveWarfareEngine(narrative_query="test", twitter_keywords=["test"])

    # --- Assert ---
    # The primary goal is to ensure initialization succeeds and narratives are loaded.
    assert len(engine.narratives) == 2
    assert not engine.narratives.empty