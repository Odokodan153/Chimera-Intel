import pytest
import psycopg2
from unittest.mock import patch, MagicMock, ANY
from typer.testing import CliRunner

# Import the specific classes and the app
from chimera_intel.core.negotiation import (
    NegotiationEngine,
    negotiation_app,
    SimulationMode,
)
from chimera_intel.core.schemas import (
    NegotiationSession,
    NegotiationParticipant,
    Message,
)

# --- Fixtures ---

@pytest.fixture
def runner():
    """Provides a Typer CliRunner instance."""
    return CliRunner()

@pytest.fixture(autouse=True)
def mock_db_params():
    """Auto-patch API_KEYS to provide mock DB parameters for all tests."""
    with patch("chimera_intel.core.negotiation.API_KEYS") as mock_keys:
        mock_keys.db_name = "test_db"
        mock_keys.db_user = "test_user"
        mock_keys.db_password = "test_pass"
        mock_keys.db_host = "localhost"
        yield mock_keys

@pytest.fixture
def mock_psycopg2_conn():
    """Mocks the psycopg2 connection used *inside* NegotiationEngine."""
    with patch("chimera_intel.core.negotiation.psycopg2.connect") as mock_connect:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.__enter__.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        yield mock_conn

@pytest.fixture
def mock_db_session():
    """Mocks the generator-based DB session used by the CLI commands."""
    with patch("chimera_intel.core.negotiation.get_db_connection") as mock_gen:
        mock_session = MagicMock()
        mock_query = MagicMock()
        
        # Configure mock_session.query to return a filterable mock
        mock_session.query.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.first.return_value = None  # Default to "not found"
        
        mock_gen.return_value = iter([mock_session])
        yield mock_session

# --- NegotiationEngine `__init__` Tests ---

@patch("chimera_intel.core.negotiation.QLearningAgent")
@patch("chimera_intel.core.negotiation.QLearningLLMAgent")
def test_engine_init_default(mock_llm_agent, mock_std_agent):
    """Tests default initialization (no LLM)."""
    engine = NegotiationEngine()
    assert isinstance(engine.rl_agent, MagicMock)
    mock_std_agent.assert_called_once_with(action_space_n=3)
    mock_llm_agent.assert_not_called()
    assert engine.llm is None

@patch("chimera_intel.core.negotiation.QLearningAgent")
@patch("chimera_intel.core.negotiation.LLMInterface")
@patch("chimera_intel.core.negotiation.QLearningLLMAgent")
def test_engine_init_llm_inference(mock_llm_agent, mock_llm_interface, mock_std_agent):
    """Tests LLM initialization in inference mode."""
    engine = NegotiationEngine(use_llm=True, mode=SimulationMode.inference)
    mock_llm_interface.assert_called_once()
    mock_llm_agent.assert_called_once_with(
        llm=mock_llm_interface.return_value,
        ethics=engine.ethical_framework,
        db_params=engine.db_params,
        action_space_n=3,
    )
    mock_std_agent.assert_not_called()

@patch("chimera_intel.core.negotiation.QLearningAgent")
@patch("chimera_intel.core.negotiation.MockLLMInterface")
@patch("chimera_intel.core.negotiation.QLearningLLMAgent")
def test_engine_init_llm_training(mock_llm_agent, mock_mock_llm, mock_std_agent):
    """Tests LLM initialization in training mode (uses MockLLMInterface)."""
    engine = NegotiationEngine(use_llm=True, mode=SimulationMode.training)
    mock_mock_llm.assert_called_once()
    mock_llm_agent.assert_called_once_with(
        llm=mock_mock_llm.return_value,
        ethics=engine.ethical_framework,
        db_params=engine.db_params,
        action_space_n=3,
    )
    mock_std_agent.assert_not_called()

@patch("chimera_intel.core.negotiation.QLearningAgent")
@patch("chimera_intel.core.negotiation.LLMInterface", side_effect=ValueError("API Key Missing"))
@patch("chimera_intel.core.negotiation.QLearningLLMAgent")
def test_engine_init_llm_failure_fallback(mock_llm_agent, mock_llm_interface, mock_std_agent):
    """Tests fallback to standard agent if LLM interface fails."""
    engine = NegotiationEngine(use_llm=True, mode=SimulationMode.inference)
    mock_llm_interface.assert_called_once()
    mock_llm_agent.assert_not_called()
    mock_std_agent.assert_called_once_with(action_space_n=3)
    assert engine.llm is None

@patch("chimera_intel.core.negotiation.QLearningAgent")
def test_engine_init_load_model_success(mock_std_agent):
    """Tests loading a model from a path."""
    mock_agent_instance = MagicMock()
    mock_std_agent.return_value = mock_agent_instance
    
    engine = NegotiationEngine(rl_model_path="fake/path.model")
    
    mock_std_agent.assert_called_once()
    mock_agent_instance.load_model.assert_called_once_with("fake/path.model")
    assert engine.rl_agent.epsilon == 0.1

@patch("chimera_intel.core.negotiation.QLearningAgent")
def test_engine_init_load_model_not_found(mock_std_agent, caplog):
    """Tests loading a model that doesn't exist."""
    mock_agent_instance = MagicMock()
    mock_agent_instance.load_model.side_effect = FileNotFoundError
    mock_std_agent.return_value = mock_agent_instance
    
    engine = NegotiationEngine(rl_model_path="bad/path.model")
    
    mock_agent_instance.load_model.assert_called_once_with("bad/path.model")
    assert "RL model not found" in caplog.text

# --- NegotiationEngine Method Tests ---

def test_get_db_connection(mock_psycopg2_conn):
    """Tests the internal DB connection method."""
    engine = NegotiationEngine(db_params={"dbname": "test"})
    conn = engine._get_db_connection()
    assert conn is not None
    psycopg2.connect.assert_called_with(dbname="test")

def test_get_db_connection_no_params():
    """Tests DB connection fails if params are not set."""
    engine = NegotiationEngine()
    conn = engine._get_db_connection()
    assert conn is None

@patch("chimera_intel.core.negotiation.psycopg2.connect", side_effect=psycopg2.OperationalError("DB Down"))
def test_get_db_connection_exception(mock_connect):
    """Tests DB connection exception handling."""
    engine = NegotiationEngine(db_params={"dbname": "test"})
    conn = engine._get_db_connection()
    assert conn is None

def test_analyze_message_intents(engine):
    """Tests the intent logic in analyze_message."""
    offer = engine.analyze_message("I offer $100.")
    assert offer["intent"] == "offer"
    
    accept = engine.analyze_message("I accept your price.")
    assert accept["intent"] == "accept"
    
    reject = engine.analyze_message("That is too high.")
    assert reject["intent"] == "rejection"
    
    neutral = engine.analyze_message("Let's talk.")
    assert neutral["intent"] == "neutral"

def test_get_reward_concession(engine):
    """Tests the reward logic for making a concession."""
    history = [
        {"sender": "user", "content": "I want $1000"},
        {"sender": "ai", "content": "I offer $800"} # This is the "last_message"
    ]
    state = engine._get_state_from_history(history)
    reward = engine.get_reward(state, history)
    # 0.1 for offer, 0.1 for concession
    assert reward == pytest.approx(0.4) 

def test_assess_batna_empty(engine):
    """Tests BATNA assessment with no alternatives."""
    result = engine.assess_batna([])
    assert result["best_alternative"] is None

def test_log_rl_step(engine, mock_psycopg2_conn):
    """Tests the RL logging method."""
    engine._log_rl_step({"state": "test"}, 1, 0.5)
    mock_psycopg2_conn.cursor.return_value.__enter__.return_value.execute.assert_called_once()
    mock_psycopg2_conn.commit.assert_called_once()

def test_log_rl_step_db_error(engine, mock_psycopg2_conn):
    """Tests exception handling in RL logging."""
    mock_psycopg2_conn.cursor.return_value.__enter__.return_value.execute.side_effect = Exception("DB Error")
    # Should not raise an exception
    engine._log_rl_step({"state": "test"}, 1, 0.5)
    mock_psycopg2_conn.commit.assert_not_called()
    mock_psycopg2_conn.close.assert_called_once()

def test_log_llm_interaction(mock_psycopg2_conn):
    """Tests the LLM logging method."""
    with patch("chimera_intel.core.negotiation.LLMInterface") as mock_llm_iface:
        with patch("chimera_intel.core.negotiation.QLearningLLMAgent") as mock_llm_agent:
            # Setup engine
            engine = NegotiationEngine(use_llm=True)
            engine.llm = mock_llm_iface.return_value
            engine.rl_agent = mock_llm_agent.return_value
            
            # Call log
            engine._log_llm_interaction({"state": "test"}, 1, 0.5, "bot response", "US")
            
            mock_psycopg2_conn.cursor.return_value.__enter__.return_value.execute.assert_called_once()
            mock_psycopg2_conn.commit.assert_called_once()

@pytest.mark.asyncio
async def test_recommend_tactic_async_non_llm(engine, mock_psycopg2_conn):
    """Tests the async recommendation path without an LLM."""
    history = []
    engine.rl_agent = MagicMock(spec=NegotiationEngine.rl_agent)
    engine.rl_agent.choose_action.return_value = 0 # Mock action
    
    rec = await engine.recommend_tactic_async(history, "US")
    
    engine.rl_agent.choose_action.assert_called_once()
    # Check that it logged the RL step
    mock_psycopg2_conn.cursor.return_value.__enter__.return_value.execute.assert_called_once()
    # Check that it returned a rule-based response
    assert rec["tactic"] == "Opening Move"

@pytest.mark.asyncio
async def test_recommend_tactic_async_with_llm(mock_psycopg2_conn):
    """Tests the async recommendation path *with* an LLM."""
    with patch("chimera_intel.core.negotiation.LLMInterface") as mock_llm_iface:
        with patch("chimera_intel.core.negotiation.QLearningLLMAgent") as mock_llm_agent_class:
            
            # Setup mock agent instance
            mock_agent_instance = MagicMock()
            mock_agent_instance.choose_action.return_value = 1
            mock_agent_instance.generate_negotiation_message.return_value = "LLM Response"
            mock_llm_agent_class.return_value = mock_agent_instance
            
            # Setup engine
            engine = NegotiationEngine(use_llm=True)
            engine.llm = mock_llm_iface.return_value
            engine.rl_agent = mock_agent_instance

            history = [{"content": "Hello", "analysis": {"sentiment": "neutral"}}]
            rec = await engine.recommend_tactic_async(history, "JP")
            
            mock_agent_instance.choose_action.assert_called_once()
            mock_agent_instance.generate_negotiation_message.assert_called_once()
            
            # Check that it returned an LLM response
            assert rec["tactic"] == "LLM-Generated Response"
            assert rec["bot_response"] == "LLM Response"
            
            # Check that it logged *both* RL and LLM steps
            assert mock_psycopg2_conn.cursor.return_value.__enter__.return_value.execute.call_count == 2


# --- Typer CLI Command Tests ---

@patch("chimera_intel.core.negotiation.plot_sentiment_trajectory")
@patch("chimera_intel.core.negotiation.asyncio.run")
@patch("chimera_intel.core.negotiation.NegotiationEngine")
def test_cli_run_simulation_exit(mock_engine_class, mock_asyncio_run, mock_plot, runner):
    """Tests the simulation loop and exiting."""
    # Arrange
    mock_engine_instance = MagicMock()
    mock_engine_class.return_value = mock_engine_instance
    
    # Mock asyncio.run to return AI responses
    mock_asyncio_run.side_effect = [
        {"bot_response": "AI Response 1"}, # Initial response
        {"bot_response": "AI Response 2"}  # Response after user input
    ]
    
    # Mock console.input to provide user input
    with patch("rich.console.Console.input", side_effect=["User message 1", "exit"]) as mock_input:
        
        # Act
        result = runner.invoke(negotiation_app, ["simulate"])

        # Assert
        assert result.exit_code == 0
        assert "--- Starting Negotiation Simulation" in result.stdout
        assert "AI: AI Response 1" in result.stdout
        assert "You: User message 1" in result.stdout
        assert "AI: AI Response 2" in result.stdout
        assert "--- Simulation Ended ---" in result.stdout
        
        # Check that it called analyze_message on user input
        mock_engine_instance.analyze_message.assert_called_with("User message 1")
        # Check that plot was called on exit
        mock_plot.assert_called_once()

@patch("chimera_intel.core.negotiation.asyncio.run")
@patch("chimera_intel.core.negotiation.NegotiationEngine")
def test_cli_run_simulation_deterministic(mock_engine_class, mock_asyncio_run, runner):
    """Tests the deterministic opponent mode."""
    mock_engine_instance = MagicMock()
    mock_engine_class.return_value = mock_engine_instance
    
    mock_asyncio_run.return_value = {"bot_response": "AI Response"}

    # Mock console.input. We patch it, but it should not be called.
    with patch("rich.console.Console.input", side_effect=["exit"]) as mock_input:
        
        # Act
        result = runner.invoke(negotiation_app, ["simulate", "--deterministic"])

        # Assert
        assert result.exit_code == 0
        mock_input.assert_not_called() # Key assertion: deterministic mode doesn't ask for input
        assert "Deterministic Opponent: I can offer a 10% reduction." in result.stdout

@patch("chimera_intel.core.negotiation.NegotiationEngine")
def test_cli_run_simulation_llm_flag(mock_engine_class, runner):
    """Tests that the --llm flag is passed to the engine."""
    with patch("chimera_intel.core.negotiation.asyncio.run", return_value={"bot_response": "AI Response"}):
        with patch("rich.console.Console.input", side_effect=["exit"]):
            runner.invoke(negotiation_app, ["simulate", "--llm"])
            
            # Check that NegotiationEngine was called with use_llm=True
            mock_engine_class.assert_called_with(
                db_params=ANY, use_llm=True, mode=SimulationMode.inference
            )

def test_cli_start(runner, mock_db_session):
    """Tests the 'start' command."""
    result = runner.invoke(negotiation_app, ["start", "Test Subject"])
    
    assert result.exit_code == 0
    assert "Negotiation session started with ID" in result.stdout
    mock_db_session.add.assert_called_once()
    mock_db_session.commit.assert_called_once()

def test_cli_join(runner, mock_db_session):
    """Tests the 'join' command."""
    mock_session = NegotiationSession(id="sid-123", subject="Test")
    mock_db_session.query.return_value.filter.return_value.first.return_value = mock_session
    
    result = runner.invoke(negotiation_app, ["join", "sid-123", "uid-456"])
    
    assert result.exit_code == 0
    assert "User uid-456 has joined negotiation sid-123" in result.stdout
    mock_db_session.add.assert_called_once_with(ANY) # Checks that an object was added
    assert isinstance(mock_db_session.add.call_args[0][0], NegotiationParticipant)
    mock_db_session.commit.assert_called_once()

def test_cli_join_not_found(runner, mock_db_session):
    """Tests the 'join' command when the session is not found."""
    # mock_db_session already defaults to returning None
    result = runner.invoke(negotiation_app, ["join", "sid-123", "uid-456"])
    
    assert result.exit_code == 0
    assert "Negotiation session with ID sid-123 not found." in result.stdout
    mock_db_session.add.assert_not_called()

def test_cli_leave(runner, mock_db_session):
    """Tests the 'leave' command."""
    mock_participant = NegotiationParticipant(session_id="sid-123", participant_id="uid-456")
    mock_db_session.query.return_value.filter.return_value.first.return_value = mock_participant
    
    result = runner.invoke(negotiation_app, ["leave", "sid-123", "uid-456"])
    
    assert result.exit_code == 0
    assert "User uid-456 has left negotiation sid-123" in result.stdout
    mock_db_session.delete.assert_called_once_with(mock_participant)
    mock_db_session.commit.assert_called_once()

def test_cli_leave_not_found(runner, mock_db_session):
    """Tests the 'leave' command when the participant is not found."""
    result = runner.invoke(negotiation_app, ["leave", "sid-123", "uid-456"])
    
    assert result.exit_code == 0
    assert "User uid-456 not found in negotiation sid-123." in result.stdout
    mock_db_session.delete.assert_not_called()

def test_cli_offer(runner, mock_db_session):
    """Tests the 'offer' command."""
    result = runner.invoke(negotiation_app, ["offer", "sid-123", "uid-456", "$100"])
    
    assert result.exit_code == 0
    assert "Offer from uid-456 in session sid-123 recorded." in result.stdout
    mock_db_session.add.assert_called_once()
    added_message = mock_db_session.add.call_args[0][0]
    assert isinstance(added_message, Message)
    assert added_message.content == "Offer: $100"

def test_cli_accept(runner, mock_db_session):
    """Tests the 'accept' command."""
    result = runner.invoke(negotiation_app, ["accept", "sid-123", "uid-456"])
    
    assert result.exit_code == 0
    assert "Acceptance from uid-456 in session sid-123 recorded." in result.stdout
    mock_db_session.add.assert_called_once()
    added_message = mock_db_session.add.call_args[0][0]
    assert added_message.content == "Offer accepted."

def test_cli_reject(runner, mock_db_session):
    """Tests the 'reject' command."""
    result = runner.invoke(negotiation_app, ["reject", "sid-123", "uid-456"])
    
    assert result.exit_code == 0
    assert "Rejection from uid-456 in session sid-123 recorded." in result.stdout
    mock_db_session.add.assert_called_once()
    added_message = mock_db_session.add.call_args[0][0]
    assert added_message.content == "Offer rejected."

def test_cli_history(runner, mock_db_session):
    """Tests the 'history' command."""
    mock_msg1 = Message(sender_id="user1", content="Hello")
    mock_msg2 = Message(sender_id="user2", content="Hi")
    mock_session = NegotiationSession(id="sid-123", subject="Test", messages=[mock_msg1, mock_msg2])
    mock_db_session.query.return_value.filter.return_value.first.return_value = mock_session
    
    result = runner.invoke(negotiation_app, ["history", "sid-123"])
    
    assert result.exit_code == 0
    assert "[user1] Hello" in result.stdout
    assert "[user2] Hi" in result.stdout

def test_cli_history_not_found(runner, mock_db_session):
    """Tests the 'history' command when the session is not found."""
    result = runner.invoke(negotiation_app, ["history", "sid-123"])
    
    assert result.exit_code == 0
    assert "Negotiation session with ID sid-123 not found." in result.stdout

# The existing tests are good unit tests for the engine's helper methods.
# We will keep them.

@pytest.fixture
def engine():
    """Provides a NegotiationEngine instance for testing."""
    return NegotiationEngine()

def test_recommend_tactic_with_reason(engine):
    """Tests that tactic recommendations include a reason."""
    history = [
        {
            "sender_id": "them",
            "content": "Let's begin.",
            "analysis": {"sentiment": "neutral", "tone_score": 0.0},
        }
    ]
    recommendation = engine.recommend_tactic(history)
    assert "tactic" in recommendation
    assert "reason" in recommendation
    assert "Collaborative Exploration" in recommendation["tactic"]

def test_recommend_tactic_with_history(engine):
    """Tests that recommendations change based on history."""
    history = [
        {
            "sender_id": "them",
            "content": "This is a terrible offer.",
            "analysis": {"tone_score": -0.8, "sentiment": "negative"},
        }
    ]
    recommendation = engine.recommend_tactic(history)
    assert "De-escalate" in recommendation["tactic"]
    assert "negative" in recommendation["reason"]

def test_full_engine_functionality(engine):
    """A comprehensive test that checks all core methods of the unified engine."""
    message = "I'm not happy with this price, it's too high."
    analysis = engine.analyze_message(message)
    assert analysis["sentiment"] == "negative"
    assert analysis["intent"] == "rejection" 

    alternatives = [
        {"name": "Supplier A", "value": 12000},
        {"name": "Supplier B", "value": 15000},
    ]
    batna_result = engine.assess_batna(alternatives)
    assert batna_result["best_alternative"]["name"] == "Supplier B"

    zopa = engine.calculate_zopa(
        our_min=10000, our_max=16000, their_min=14000, their_max=18000
    )
    assert zopa == (14000, 16000)

    history = [{"sender_id": "them", "content": message, "analysis": analysis}]
    recommendation = engine.recommend_tactic(history)
    assert "De-escalate" in recommendation["tactic"]
    assert "negative" in recommendation["reason"]

    scenario = {
        "our_min": 10000,
        "our_max": 16000,
        "their_min": 14000,
        "their_max": 18000,
    }
    simulation = engine.simulate_outcome(scenario)
    assert "settlement_point" in simulation
    assert simulation["outcome"] == "Deal is Possible"

def test_get_reward(engine):
    """Tests the get_reward function to ensure it calculates rewards as expected."""
    positive_state = {"last_message_sentiment": "positive"}
    negative_state = {"last_message_sentiment": "negative"}
    neutral_state = {"last_message_sentiment": "neutral"}
    offer_state = {"last_message_content": "I offer $100"}
    accept_state = {"last_message_content": "I accept"}
    reject_state = {"last_message_content": "I reject"}

    empty_history = []
    assert engine.get_reward(positive_state, empty_history) == 0.2
    assert engine.get_reward(negative_state, empty_history) == -0.2
    assert engine.get_reward(neutral_state, empty_history) == 0
    assert engine.get_reward(offer_state, empty_history) > 0.2 # 0.3 for offer
    assert engine.get_reward(accept_state, empty_history) == 1.0 # 1.0 for accept
    assert engine.get_reward(reject_state, empty_history) == -0.5 # -0.5 for reject

def test_simulate_outcome(engine):
    """Tests the negotiation outcome simulation."""
    scenario_deal = {
        "our_min": 10000,
        "our_max": 15000,
        "their_min": 12000,
        "their_max": 18000,
    }
    scenario_no_deal = {
        "our_min": 10000,
        "our_max": 11000,
        "their_min": 12000,
        "their_max": 18000,
    }
    result_deal = engine.simulate_outcome(scenario_deal)
    result_no_deal = engine.simulate_outcome(scenario_no_deal)

    assert result_deal["outcome"] == "Deal is Possible"
    assert result_no_deal["outcome"] == "No Deal Likely"