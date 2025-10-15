import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import pandas as pd

from chimera_intel.core.cognitive_warfare_engine import (
    cognitive_warfare_app,
    CognitiveWarfareEngine,
)

runner = CliRunner()

# Mock data for narrative and social media modules

MOCK_NARRANTIVE_DATA = [
    {"content": "There is an unacceptable risk of collapse!", "sentiment": "negative"},
    {
        "content": "The corrupt elites are causing this problem.",
        "sentiment": "negative",
    },
]


def create_mock_twitter_result(tweets, error=None):
    mock_result = MagicMock()
    mock_result.tweets = tweets
    mock_result.error = error
    return mock_result


def create_mock_tweet(text):
    mock_tweet = MagicMock()
    mock_tweet.text = text
    return mock_tweet


MOCK_TWEETS = [
    create_mock_tweet("This is an outrage! #injustice"),
    create_mock_tweet("Warning: a huge threat is coming."),
]


@pytest.fixture
def mock_data_sources():
    """Mocks the track_narrative and monitor_twitter_stream functions."""
    with patch(
        "chimera_intel.core.cognitive_warfare_engine.track_narrative"
    ) as mock_narrative, patch(
        "chimera_intel.core.cognitive_warfare_engine.monitor_twitter_stream"
    ) as mock_social:

        mock_narrative.return_value = MOCK_NARRANTIVE_DATA
        mock_social.return_value = create_mock_twitter_result(tweets=MOCK_TWEETS)

        yield {"narrative": mock_narrative, "social": mock_social}


def test_cli_command(mock_data_sources):
    """Tests the full CLI command execution."""
    result = runner.invoke(
        cognitive_warfare_app,
        [
            "deploy-shield",
            "--narrative",
            "economic stability",
            "--keywords",
            "risk,threat",
        ],
    )
    assert result.exit_code == 0
    assert "Loading narratives" in result.stdout
    assert "Analyzing cognitive triggers" in result.stdout
    assert "Detected Cognitive Triggers" in result.stdout
    assert "Fear" in result.stdout
    assert "Anger" in result.stdout
    assert "Generating Narrative Shield" in result.stdout
    assert "Generated 'Digital Antibody'" in result.stdout


def test_trigger_identification(mock_data_sources):
    """Tests the logic for identifying psychological triggers in text."""
    engine = CognitiveWarfareEngine(narrative_query="test", twitter_keywords=None)

    fear_text = "There is a grave danger and a huge threat."
    anger_text = "This is an outrage, a total betrayal!"
    tribal_text = "It's us vs them, the elites are the problem."

    assert "fear" in engine._identify_triggers(fear_text)
    assert "anger" in engine._identify_triggers(anger_text)
    assert "tribalism" in engine._identify_triggers(tribal_text)
    assert not engine._identify_triggers("This is a neutral statement.")


def test_counter_narrative_generation(mock_data_sources):
    """Tests the generation of a counter-narrative based on dominant triggers."""
    engine = CognitiveWarfareEngine(narrative_query="test query")

    # Manually create a dataframe with a dominant 'fear' trigger

    engine.narratives = pd.DataFrame(
        [
            {"content": "danger risk threat", "triggers": ["fear"]},
            {"content": "another threat", "triggers": ["fear"]},
            {"content": "some outrage", "triggers": ["anger"]},
        ]
    )

    # We need to capture the print output to verify the result

    with patch("rich.console.Console.print") as mock_print:
        engine.generate_narrative_shield()

        # Check if the output contains the fear-based counter-narrative

        args_list = mock_print.call_args_list
        output_text = " ".join(str(args[0]) for args, kwargs in args_list)

        assert "Dominant Trigger:" in output_text
        assert "Fear" in output_text
        assert "mitigate unnecessary alarm" in output_text
