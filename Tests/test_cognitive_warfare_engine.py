import pytest
import pandas as pd
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.cognitive_warfare_engine import (
    CognitiveWarfareEngine,
    cognitive_warfare_app,
)
from chimera_intel.core.schemas import TwitterMonitoringResult, Tweet

# --- Fixtures ---

@pytest.fixture
def runner():
    """Provides a Typer CliRunner instance."""
    return CliRunner()

@pytest.fixture
def mock_narrative_data():
    """Mock data from track_narrative."""
    return [
        {"content": "There is a great risk of collapse.", "source": "Web/News", "sentiment": "Negative"},
        {"content": "This is corrupt and must be stopped.", "source": "Blog", "sentiment": "Negative"},
        {"content": "A new solution brings hope.", "source": "Web/News", "sentiment": "Positive"}
    ]

@pytest.fixture
def mock_twitter_data_success():
    """Mock successful data from monitor_twitter_stream."""
    return TwitterMonitoringResult(
        query="test",
        total_tweets_found=1,
        tweets=[Tweet(id="1", text="This is an outrage!", author_id="123", created_at="2023-01-01T12:00:00Z")]
    )

@pytest.fixture
def mock_twitter_data_error():
    """Mock error data from monitor_twitter_stream."""
    return TwitterMonitoringResult(
        query="test",
        total_tweets_found=0,
        tweets=[],
        error="API Error"
    )

@pytest.fixture
def mock_cwe_dependencies(mocker, mock_narrative_data, mock_twitter_data_success):
    """Mocks the dependencies of the CognitiveWarfareEngine for most tests."""
    mocker.patch(
        "chimera_intel.core.cognitive_warfare_engine.track_narrative",
        return_value=mock_narrative_data
    )
    mocker.patch(
        "chimera_intel.core.cognitive_warfare_engine.monitor_twitter_stream",
        return_value=mock_twitter_data_success
    )

# --- Original Test (Kept for regression) ---

def test_cognitive_warfare_engine_initialization(mock_cwe_dependencies):
    """
    Tests that the CognitiveWarfareEngine initializes correctly with mocked dependencies.
    """
    # --- Act ---
    engine = CognitiveWarfareEngine(narrative_query="test", twitter_keywords=["test"])

    # --- Assert ---
    assert len(engine.narratives) == 4 # 3 from narrative, 1 from twitter
    assert not engine.narratives.empty
    assert "Web/News" in engine.narratives["source"].values
    assert "Blog" in engine.narratives["source"].values
    assert "Twitter" in engine.narratives["source"].values

# --- Extended Tests ---

def test_cwe_init_no_twitter_keywords(mocker, mock_narrative_data):
    """Tests initialization *without* providing twitter_keywords."""
    mock_track = mocker.patch(
        "chimera_intel.core.cognitive_warfare_engine.track_narrative",
        return_value=mock_narrative_data
    )
    mock_monitor = mocker.patch(
        "chimera_intel.core.cognitive_warfare_engine.monitor_twitter_stream"
    )

    # Act
    engine = CognitiveWarfareEngine(narrative_query="test", twitter_keywords=None)
    
    # Assert
    assert len(engine.narratives) == 3
    mock_track.assert_called_once_with("test")
    mock_monitor.assert_not_called() # Should not be called

def test_cwe_init_twitter_error(mocker, mock_narrative_data, mock_twitter_data_error):
    """Tests initialization when monitor_twitter_stream returns an error."""
    mocker.patch(
        "chimera_intel.core.cognitive_warfare_engine.track_narrative",
        return_value=mock_narrative_data
    )
    mocker.patch(
        "chimera_intel.core.cognitive_warfare_engine.monitor_twitter_stream",
        return_value=mock_twitter_data_error
    )
    
    # Act
    engine = CognitiveWarfareEngine(narrative_query="test", twitter_keywords=["test"])
    
    # Assert
    assert len(engine.narratives) == 3 # Should only contain narrative data
    assert "Twitter" not in engine.narratives["source"].values

def test_cwe_init_no_narratives_found(mocker, capsys):
    """Tests initialization when no sources return data."""
    mocker.patch(
        "chimera_intel.core.cognitive_warfare_engine.track_narrative",
        return_value=[]
    )
    mocker.patch(
        "chimera_intel.core.cognitive_warfare_engine.monitor_twitter_stream",
        return_value=TwitterMonitoringResult(query="test", tweets=[])
    )
    
    # Act
    engine = CognitiveWarfareEngine(narrative_query="test", twitter_keywords=["test"])
    
    # Assert
    assert engine.narratives.empty
    captured = capsys.readouterr()
    assert "Warning: No narratives loaded" in captured.out

def test_engine_identify_triggers(mock_cwe_dependencies):
    """Directly tests the _identify_triggers helper method."""
    engine = CognitiveWarfareEngine(narrative_query="test")
    
    fear_text = "There is a massive danger and risk of collapse."
    assert engine._identify_triggers(fear_text) == ["fear"]
    
    anger_text = "This is an outrage, so corrupt!"
    assert engine._identify_triggers(anger_text) == ["anger"]
    
    tribal_text = "It's us vs them, the elite are the problem."
    assert engine._identify_triggers(tribal_text) == ["tribalism"]
    
    hope_text = "A new solution brings hope for the future."
    assert engine._identify_triggers(hope_text) == ["hope"]
    
    multiple_text = "I fear this is an outrage."
    assert "fear" in engine._identify_triggers(multiple_text)
    assert "anger" in engine._identify_triggers(multiple_text)
    
    none_text = "This is a neutral statement."
    assert engine._identify_triggers(none_text) == []

def test_engine_analyze_narratives(mock_cwe_dependencies, capsys):
    """Tests the full analysis and reporting workflow."""
    engine = CognitiveWarfareEngine(narrative_query="test", twitter_keywords=["test"])
    
    # Act
    engine.analyze_narratives()
    
    # Assert
    captured = capsys.readouterr()
    assert "Analyzing cognitive triggers" in captured.out
    
    # Check narrative flow counts
    assert "Web/News: 2 narratives" in captured.out
    assert "Blog: 1 narratives" in captured.out
    assert "Twitter: 1 narratives" in captured.out
    
    # Check trigger report
    assert "Detected Cognitive Triggers" in captured.out
    assert "Fear" in captured.out
    assert "Anger" in captured.out
    assert "Hope" in captured.out
    
    # Check dataframe
    assert "triggers" in engine.narratives.columns
    assert engine.narratives.iloc[0]["triggers"] == ["fear"] # "risk of collapse"
    # FIX: This assertion will now pass, as "must" no longer matches "us"
    assert engine.narratives.iloc[1]["triggers"] == ["anger"] # "corrupt"
    assert engine.narratives.iloc[2]["triggers"] == ["hope"] # "hope"
    assert engine.narratives.iloc[3]["triggers"] == ["anger"] # "outrage"

# FIX: Removed the problematic @patch decorators.
# Instead, wrap the engine instantiation in a `with patch` block
# to prevent network calls, as the test logic relies on manually
# setting the dataframe to empty *after* instantiation.
def test_engine_analyze_narratives_empty(capsys):
    """Tests that analyze_narratives exits early if no narratives were loaded."""
    # Use 'with patch' to mock dependencies during __init__
    with patch("chimera_intel.core.cognitive_warfare_engine.track_narrative", return_value=[]), \
         patch("chimera_intel.core.cognitive_warfare_engine.monitor_twitter_stream", 
               return_value=TwitterMonitoringResult(query="test", tweets=[])):
        engine = CognitiveWarfareEngine(narrative_query="test")
    
    engine.narratives = pd.DataFrame() # Force empty
    
    engine.analyze_narratives()
    
    captured = capsys.readouterr()
    assert "Analyzing cognitive triggers" not in captured.out

def test_engine_generate_narrative_shield(mock_cwe_dependencies, capsys):
    """Tests the counter-narrative generation."""
    engine = CognitiveWarfareEngine(narrative_query="divisive topic", twitter_keywords=["test"])
    engine.analyze_narratives() # Run analysis to populate triggers
    
    # Act
    engine.generate_narrative_shield()
    
    # Assert
    captured = capsys.readouterr()
    assert "Generating Narrative Shield" in captured.out
    
    # 'anger' appears twice ("corrupt", "outrage"), so it should be the dominant trigger
    assert "Dominant Trigger:" in captured.out
    assert "Anger" in captured.out
    
    # Check that the correct template was used
    assert "The strong emotions surrounding 'divisive topic' are understandable." in captured.out
    
def test_engine_generate_shield_default_trigger(mocker, capsys):
    """Tests that the default shield is used if no triggers are found."""
    mocker.patch(
        "chimera_intel.core.cognitive_warfare_engine.track_narrative",
        return_value=[{"content": "Neutral news.", "source": "Web/News"}]
    )
    mocker.patch(
        "chimera_intel.core.cognitive_warfare_engine.monitor_twitter_stream",
        return_value=TwitterMonitoringResult(query="test", tweets=[])
    )
    
    engine = CognitiveWarfareEngine(narrative_query="neutral topic")
    engine.analyze_narratives()
    
    # Act
    engine.generate_narrative_shield()
    
    # Assert
    captured = capsys.readouterr()
    assert "Dominant Trigger:" in captured.out
    assert "Default" in captured.out
    assert "A balanced perspective on 'neutral topic' requires" in captured.out
    
# FIX: Removed the problematic @patch decorators.
# Use 'with patch' block for the same reasons as test_engine_analyze_narratives_empty
def test_engine_generate_shield_empty(capsys):
    """Tests that generate_narrative_shield exits early if no narratives/analysis."""
    with patch("chimera_intel.core.cognitive_warfare_engine.track_narrative", return_value=[]), \
         patch("chimera_intel.core.cognitive_warfare_engine.monitor_twitter_stream", 
               return_value=TwitterMonitoringResult(query="test", tweets=[])):
        engine = CognitiveWarfareEngine(narrative_query="test")
    
    engine.narratives = pd.DataFrame() # Force empty
    
    engine.generate_narrative_shield()
    
    captured = capsys.readouterr()
    assert "Generating Narrative Shield" not in captured.out

# --- Typer CLI Command Tests ---

@patch("chimera_intel.core.cognitive_warfare_engine.CognitiveWarfareEngine")
def test_cli_deploy_shield(mock_engine_class, runner):
    """Tests the 'deploy-shield' command."""
    # Arrange
    mock_engine_instance = MagicMock()
    mock_engine_class.return_value = mock_engine_instance
    
    # Act
    result = runner.invoke(
        cognitive_warfare_app,
        ["deploy-shield", "--narrative", "test topic", "--keywords", "key1,key2"],
    )
    
    # Assert
    assert result.exit_code == 0
    # Check that engine was called correctly
    mock_engine_class.assert_called_with(
        narrative_query="test topic",
        twitter_keywords=["key1", "key2"]
    )
    # Check that methods were called
    mock_engine_instance.analyze_narratives.assert_called_once()
    mock_engine_instance.generate_narrative_shield.assert_called_once()
    
@patch("chimera_intel.core.cognitive_warfare_engine.CognitiveWarfareEngine")
def test_cli_deploy_shield_no_keywords(mock_engine_class, runner):
    """Tests the 'deploy-shield' command without optional keywords."""
    mock_engine_instance = MagicMock()
    mock_engine_class.return_value = mock_engine_instance
    
    result = runner.invoke(
        cognitive_warfare_app,
        ["deploy-shield", "--narrative", "test topic"],
    )
    
    assert result.exit_code == 0
    mock_engine_class.assert_called_with(
        narrative_query="test topic",
        twitter_keywords=None
    )
    mock_engine_instance.analyze_narratives.assert_called_once()
    
@patch("chimera_intel.core.cognitive_warfare_engine.run_humint_scenario")
@patch("chimera_intel.core.cognitive_warfare_engine.HumintScenario")
def test_cli_run_scenario_success(mock_scenario_class, mock_run_scenario, runner):
    """Tests the 'run_scenario' command success path."""
    # Arrange
    mock_scenario_instance = MagicMock()
    mock_scenario_class.return_value = mock_scenario_instance
    mock_run_scenario.return_value = {"success": True, "outcome": "Info obtained"}
    
    # Act
    result = runner.invoke(
        cognitive_warfare_app,
        ["run_scenario", "--scenario-type", "elicitation", "--target", "Asset A"],
    )
    
    # Assert
    assert result.exit_code == 0
    mock_scenario_class.assert_called_with(scenario_type="elicitation", target="Asset A")
    mock_run_scenario.assert_called_with(mock_scenario_instance)
    assert "Running HUMINT scenario 'elicitation'" in result.stdout
    assert "Scenario successful:" in result.stdout
    assert "Info obtained" in result.stdout

@patch("chimera_intel.core.cognitive_warfare_engine.run_humint_scenario")
@patch("chimera_intel.core.cognitive_warfare_engine.HumintScenario")
def test_cli_run_scenario_failure(mock_scenario_class, mock_run_scenario, runner):
    """Tests the 'run_scenario' command failure path."""
    mock_run_scenario.return_value = {"success": False, "outcome": "Target spooked"}
    
    result = runner.invoke(
        cognitive_warfare_app,
        ["run_scenario", "--scenario-type", "infiltration", "--target", "Org B"],
    )
    
    assert result.exit_code == 0
    assert "Scenario failed:" in result.stdout
    assert "Target spooked" in result.stdout

@patch("chimera_intel.core.cognitive_warfare_engine.run_humint_scenario", side_effect=Exception("Test Error"))
@patch("chimera_intel.core.cognitive_warfare_engine.HumintScenario")
def test_cli_run_scenario_exception(mock_scenario_class, mock_run_scenario, runner):
    """Tests the 'run_scenario' command exception handler."""
    result = runner.invoke(
        cognitive_warfare_app,
        ["run_scenario", "--scenario-type", "error", "--target", "C"],
    )
    
    assert result.exit_code == 0
    assert "An error occurred:" in result.stdout
    assert "Test Error" in result.stdout