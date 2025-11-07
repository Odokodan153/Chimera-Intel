import pytest
import asyncio
from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock
from chimera_intel.core.mlint_schemas import SwiftMessage
from fastapi.testclient import TestClient
from typer.testing import CliRunner
import pandas as pd

# --- Important: Import the 'api_app' and 'cli_app' from mlint
# This assumes your project is installed in editable mode (pip install -e .)
from chimera_intel.core.mlint import api_app, cli_app, load_models
from chimera_intel.core.mlint_config import settings
from chimera_intel.core.schemas import Transaction
from chimera_intel.core import mlint_intel, mlint_ai, mlint_graph
from chimera_intel.core.mlint_schemas import RiskLevel, GnnAnomalyResult, Entity, EntityType
# Mark all tests in this file as asyncio
pytestmark = pytest.mark.asyncio


# --- Fixtures ---

@pytest.fixture(scope="module")
def client():
    """Fixture for the FastAPI TestClient."""
    # Patch external services *before* creating the client
    with patch("chimera_intel.core.mlint.AIOKafkaConsumer", new_callable=AsyncMock) as mock_consumer, \
         patch("chimera_intel.core.mlint.AIOKafkaProducer", new_callable=AsyncMock) as mock_producer, \
         patch("chimera_intel.core.mlint.pika.BlockingConnection") as mock_pika, \
         patch("chimera_intel.core.mlint.GraphAnalyzer", new_callable=AsyncMock) as mock_graph, \
         patch("chimera_intel.core.mlint_analysis.redis_client", new_callable=MagicMock) as mock_redis, \
         patch("chimera_intel.core.mlint.load_models") as mock_load_models:
        
        # Configure mocks
        mock_redis.ping.return_value = True
        
        # Start the TestClient, which triggers the 'startup' event
        with TestClient(api_app) as test_client:
            yield test_client

@pytest.fixture
def mock_kafka_message():
    """Creates a mock aiokafka message."""
    msg = MagicMock()
    msg.value = {
        "tx_id": "tx-123",
        "from_entity": "acct:sender",
        "to_entity": "acct:receiver",
        "amount": 1000.0,
        "currency": "USD",
        "timestamp": "2025-11-07T18:00:00Z"
    }
    # Mock headers for HMAC signature
    msg.headers = [('X-Signature', 'mock_valid_signature')]
    return msg

@pytest.fixture
def cli_runner():
    """Fixture for the Typer CLI runner."""
    return CliRunner()


# --- Test Cases ---

class TestMLintProduction:

    # --- Task 1 & 7: API and Model Lifecycle Tests ---
    def test_health_endpoint(self, client: TestClient):
        """Tests the /health endpoint."""
        # Mock the metadata loaded during startup
        with patch("chimera_intel.core.mlint.MODEL_METADATA", {"xgb_model": {"version": "test.v1"}}):
            response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["model_versions"]["xgb_model"]["version"] == "test.v1"

    def test_refresh_models_endpoint_unauthorized(self, client: TestClient):
        """Tests the /models/refresh endpoint without an API key."""
        response = client.post("/models/refresh")
        assert response.status_code == 403 # HTTP 403 Forbidden
        assert "Invalid API Key" in response.json()["detail"]

    def test_refresh_models_endpoint_authorized(self, client: TestClient):
        """Tests the /models/refresh endpoint *with* a valid API key."""
        # Mock the settings to have a key
        with patch.object(settings, "ADMIN_API_KEY", "test-key-123"), \
             patch("chimera_intel.core.mlint.load_models") as mock_load:
            
            headers = {"X-API-Key": "test-key-123"}
            response = client.post("/models/refresh", headers=headers)
        
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        mock_load.assert_called_with(force=True)

    # --- Task 1: Model Training Metadata Test ---
    def test_train_models_command_writes_metadata(self, cli_runner: CliRunner):
        """Tests that the train-models CLI command writes .json metadata files."""
        
        # Mock all file I/O and heavy libraries
        with patch("pandas.read_csv", return_value=pd.DataFrame({"amount": [1,2,3], "feature2": [4,5,6]})), \
             patch("joblib.dump") as mock_joblib_dump, \
             patch("builtins.open", new_callable=MagicMock) as mock_open:
            
            # Use mock_open.return_value as the file handle
            mock_file_handle = mock_open.return_value.__enter__.return_value
            
            # Run the command
            result = cli_runner.invoke(cli_app, [
                "train-models", 
                "dummy_features.csv",
                "--labeled-file", "dummy_labels.csv"
            ])

        assert result.exit_code == 0
        
        # Check that we called 'open' for both metadata files
        call_args_list = mock_open.call_args_list
        assert any(call[0][0] == f"{settings.iso_forest_model_path}.json" for call in call_args_list)
        assert any(call[0][0] == f"{settings.supervised_model_path}.json" for call in call_args_list)
        
        # Check that we wrote JSON data
        assert "Wrote metadata" in result.stdout

    # --- Task 2 & 3: Analysis and Redis/Graph Integration ---
    @patch("chimera_intel.core.mlint_analysis.redis_client")
    async def test_analyze_transaction_risk_uses_redis(self, mock_redis_client):
        """Tests that the analysis pipeline calls Redis for history."""
        from chimera_intel.core.mlint_analysis import analyze_transaction_risk

        # Setup mocks
        mock_iso = MagicMock()
        mock_xgb = MagicMock()
        mock_redis_client.lrange.return_value = [] # Return empty history
        mock_redis_client.pipeline.return_value = MagicMock()
        
        tx = Transaction(
            tx_id="tx-redis-test",
            from_entity="acct:test",
            to_entity="acct:other",
            amount=100,
            currency="USD",
            timestamp=datetime.now()
        )
        
        await analyze_transaction_risk(
            tx, mock_iso, mock_xgb, settings.feature_order
        )
        
        # Assert Redis was called
        mock_redis_client.lrange.assert_called_with("acct:test", 0, 99)
        mock_redis_client.pipeline.return_value.lpush.assert_called_with("acct:test", tx.json())
        mock_redis_client.pipeline.return_value.ltrim.assert_called_with("acct:test", 0, 99)

    # --- Task 5: Advanced SWIFT Analysis Test ---
    @patch("chimera_intel.core.mlint_analysis.analyze_swift_text_ai", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint_analysis.swift_parser.parse_mt103")
    async def test_analyze_swift_message_uses_parser_and_ai(self, mock_parse, mock_analyze_ai):
        """Tests that the SWIFT analyzer uses the parser and AI."""
        from chimera_intel.core.mlint_analysis import analyze_swift_message
        
        # Setup mocks
        mock_parse.return_value = {
            "sender": "SENDER NAME",
            "beneficiary": "BENEFICIARY NAME",
            "purpose": "payment for goods"
        }
        mock_analyze_ai.return_value = ["Vague Payment Description"]
        
        msg = SwiftMessage(
            mt_type="MT103",
            sender_bic="BANKAUSXXX",
            receiver_bic="BANKBUSXXX",
            amount=5000,
            currency="AUD",
            raw_content=":50K:SENDER NAME\n:59:BENEFICIARY NAME\n:70:payment for goods\n-}"
        )
        
        result = await analyze_swift_message(msg)
        
        # Assert parser was called
        mock_parse.assert_called_with(msg.raw_content)
        
        # Assert AI was called with the *parsed text*
        expected_ai_text = "Sender: SENDER NAME. Beneficiary: BENEFICIARY NAME. Purpose: payment for goods"
        mock_analyze_ai.assert_called_with(expected_ai_text)
        
        # Assert AI results are in the final flags
        assert "Vague Payment Description" in result.red_flags

    # --- Task 4, 6, 8: Kafka Consumer Tests ---
    
    @patch("chimera_intel.core.mlint._verify_message_signature", return_value=True)
    @patch("chimera_intel.core.mlint.analyze_transaction_risk", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint.GraphAnalyzer.add_transactions_batch", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint._send_to_dlq", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint.AIOKafkaConsumer")
    async def test_kafka_consumer_happy_path(
        self, mock_consumer_class, mock_send_to_dlq, mock_add_batch, 
        mock_analyze, mock_verify_sig, mock_kafka_message
    ):
        """Tests the Kafka consumer's successful processing path."""
        from chimera_intel.core.mlint import _run_kafka_consumer, METRIC_TRANSACTIONS_PROCESSED
        
        # Setup consumer mock
        mock_consumer_instance = mock_consumer_class.return_value
        mock_consumer_instance.__aiter__.return_value = [mock_kafka_message]
        mock_consumer_instance.commit = AsyncMock()
        
        mock_graph = AsyncMock()
        shutdown_event = asyncio.Event()

        # Run the consumer for one message
        await _run_kafka_consumer(mock_graph, shutdown_event)
        
        # 1. Assert signature was checked
        mock_verify_sig.assert_called_once()
        
        # 2. Assert analysis was called
        mock_analyze.assert_called_once()
        
        # 3. Assert graph batching was called (on shutdown flush)
        mock_add_batch.assert_called_once()
        
        # 4. Assert Kafka commit was called
        mock_consumer_instance.commit.assert_called()
        
        # 5. Assert DLQ was *NOT* called
        mock_send_to_dlq.assert_not_called()

    @patch("chimera_intel.core.mlint._verify_message_signature", return_value=True)
    @patch("chimera_intel.core.mlint.analyze_transaction_risk", side_effect=Exception("Analysis Failed!"))
    @patch("chimera_intel.core.mlint.GraphAnalyzer.add_transactions_batch", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint._send_to_dlq", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint.AIOKafkaConsumer")
    async def test_kafka_consumer_analysis_failure_sends_to_dlq(
        self, mock_consumer_class, mock_send_to_dlq, mock_add_batch, 
        mock_analyze, mock_verify_sig, mock_kafka_message
    ):
        """Tests that a processing failure sends the message to the DLQ."""
        from chimera_intel.core.mlint import _run_kafka_consumer
        
        mock_consumer_instance = mock_consumer_class.return_value
        mock_consumer_instance.__aiter__.return_value = [mock_kafka_message]
        mock_consumer_instance.commit = AsyncMock()
        
        mock_graph = AsyncMock()
        shutdown_event = asyncio.Event()

        await _run_kafka_consumer(mock_graph, shutdown_event)
        
        # 1. Assert analysis was called (and failed)
        mock_analyze.assert_called_once()
        
        # 2. Assert DLQ *WAS* called
        mock_send_to_dlq.assert_called_once_with(
            mock_kafka_message.value, settings.kafka_dlq_topic, "transaction"
        )
        
        # 3. Assert Kafka commit was *STILL* called (to move past bad message)
        mock_consumer_instance.commit.assert_called()
        
        # 4. Assert graph batch was *NOT* called (as tx failed)
        mock_add_batch.assert_not_called() # Flushed on shutdown, but buffer was empty

    @patch("chimera_intel.core.mlint._verify_message_signature", return_value=False)
    @patch("chimera_intel.core.mlint.analyze_transaction_risk", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint._send_to_dlq", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint.AIOKafkaConsumer")
    async def test_kafka_consumer_security_failure_sends_to_dlq(
        self, mock_consumer_class, mock_send_to_dlq, mock_analyze, 
        mock_verify_sig, mock_kafka_message
    ):
        """Tests that a bad HMAC signature sends to DLQ."""
        from chimera_intel.core.mlint import _run_kafka_consumer
        
        mock_consumer_instance = mock_consumer_class.return_value
        mock_consumer_instance.__aiter__.return_value = [mock_kafka_message]
        mock_consumer_instance.commit = AsyncMock()
        
        mock_graph = AsyncMock()
        shutdown_event = asyncio.Event()

        await _run_kafka_consumer(mock_graph, shutdown_event)
        
        # 1. Assert signature was checked
        mock_verify_sig.assert_called_once()
        
        # 2. Assert analysis was *NOT* called
        mock_analyze.assert_not_called()
        
        # 3. Assert DLQ *WAS* called
        mock_send_to_dlq.assert_called_once()
        
        # 4. Assert Kafka commit was *STILL* called
        mock_consumer_instance.commit.assert_called()



# --- Mocks and Fixtures ---

@pytest.fixture
def mock_models():
    """Mocks the IsolationForest and XGBoost models."""
    mock_iso = MagicMock()
    mock_xgb = MagicMock()
    return mock_iso, mock_xgb

@pytest.fixture
def mock_redis_client():
    """Mocks the redis client used in mlint_analysis."""
    # We patch the client where it is *used*
    with patch("chimera_intel.core.mlint_analysis.redis_client", new_callable=MagicMock) as mock_redis:
        mock_redis.ping.return_value = True
        mock_redis.lrange.return_value = [] # Default: empty history
        mock_redis.pipeline.return_value = MagicMock()
        yield mock_redis

@pytest.fixture
def mock_neo4j_driver():
    """Mocks the neo4j driver used in mlint_graph."""
    with patch("neo4j.AsyncGraphDatabase.driver") as mock_driver_class:
        mock_driver_instance = mock_driver_class.return_value
        mock_driver_instance.session.return_value = AsyncMock()
        mock_driver_instance.session.return_value.__aenter__.return_value.run = AsyncMock()
        mock_driver_instance.session.return_value.__aenter__.return_value.single = AsyncMock()
        mock_driver_instance.closed.return_value = False
        yield mock_driver_instance

# --- `mlint_analysis.py` Tests (Task 2 & 5) ---

class TestMLintAnalysis:

    def test_swift_parser_mt103(self):
        """Tests the SwiftParser for field extraction (Task 5)."""
        from chimera_intel.core.mlint_analysis import swift_parser
        raw_mt103 = (
            "{1:F01BANKDEFFXXX2222123456}{2:O1031200050101BANKUSNYXXXX12345678900501011201N}"
            "{3:{108:MT103}}{4:\n"
            ":20:SENDERREF\n"
            ":50K:/1234567890\n"
            "ORDERING CUSTOMER NAME\n"
            "ORDERING ADDRESS\n"
            ":59:/9876543210\n"
            "BENEFICIARY NAME\n"
            "BENEFICIARY ADDRESS\n"
            ":70:/RFB/PAYMENT FOR INVOICE 123\n"
            "-}{5:{MAC:00000000}{CHK:1234567890AB}}"
        )
        parsed = swift_parser.parse_mt103(raw_mt103)
        assert parsed["sender"] == "ORDERING ADDRESS" # Simple parser takes last line
        assert parsed["beneficiary"] == "BENEFICIARY ADDRESS"
        assert parsed["purpose"] == "/RFB/PAYMENT FOR INVOICE 123"

    @patch("chimera_intel.core.mlint_ai.analyze_swift_text_ai", new_callable=AsyncMock)
    async def test_analyze_swift_message_risk(self, mock_analyze_ai):
        """Tests the SWIFT analysis pipeline (Task 5)."""
        from chimera_intel.core.mlint_analysis import analyze_swift_message
        
        # 1. Test High-Risk Jurisdiction
        msg_iran = SwiftMessage(
            mt_type="MT103", sender_bic="BANKDEFFXXX", receiver_bic="BANKIRTHXXX", # IR = Iran
            amount=5000, currency="EUR", raw_content=":70:payment"
        )
        result_iran = await analyze_swift_message(msg_iran)
        assert result_iran.risk_level == RiskLevel.CRITICAL
        assert "High-risk jurisdiction detected" in result_iran.red_flags

        # 2. Test AI Risk
        mock_analyze_ai.return_value = ["Sanctions Evasion Language"]
        msg_ai = SwiftMessage(
            mt_type="MT103", sender_bic="BANKDEFFXXX", receiver_bic="BANKUSNYXXX",
            amount=5000, currency="USD", raw_content=":70:humanitarian aid"
        )
        result_ai = await analyze_swift_message(msg_ai)
        assert result_ai.risk_level == RiskLevel.HIGH
        assert "Sanctions Evasion Language" in result_ai.red_flags

    def test_get_and_update_historical_data_redis(self, mock_redis_client):
        """Tests the Redis get/update logic (Task 2)."""
        # --- FIX: Import the constant used in the test ---
        from chimera_intel.core.mlint_analysis import get_historical_data, update_historical_data, HISTORY_MAX_LEN
        
        # Test Get
        tx_json = '{"tx_id": "tx-hist-1", "from_entity": "acct:hist", "to_entity": "acct:other", "amount": 100, "currency": "USD", "timestamp": "2025-11-01T12:00:00Z"}'
        mock_redis_client.lrange.return_value = [tx_json]
        history = get_historical_data("acct:hist")
        
        assert len(history) == 1
        assert history[0].tx_id == "tx-hist-1"
        # This assertion now works
        mock_redis_client.lrange.assert_called_with("acct:hist", 0, HISTORY_MAX_LEN - 1)
        
        # Test Update
        tx = Transaction(
            tx_id="tx-hist-2", from_entity="acct:hist", to_entity="acct:new",
            amount=200, currency="USD", timestamp=datetime.now()
        )
        update_historical_data(tx)
        
        mock_pipeline = mock_redis_client.pipeline.return_value
        mock_pipeline.lpush.assert_called_with("acct:hist", tx.json())
        # This assertion now works
        mock_pipeline.ltrim.assert_called_with("acct:hist", 0, HISTORY_MAX_LEN - 1)
        mock_pipeline.execute.assert_called_once()


# --- `mlint_intel.py` Tests (Task 6) ---

class TestMLintIntel:

    @patch("chimera_intel.core.mlint_intel.NewsApiClient")
    @patch("chimera_intel.core.mlint_clients.RefinitivSanctionsClient", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint_clients.OpenCorporatesClient", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint_clients.ChainalysisClient", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint_clients.OpenSanctionsPepClient", new_callable=AsyncMock)
    async def test_gather_entity_intelligence_failure_metrics(
        self, mock_pep, mock_chain, mock_ubo, mock_sanctions, mock_news
    ):
        """Tests that a task failure is caught and metrics are incremented (Task 6)."""
        
        # Setup mocks
        mock_sanctions.check_entity.side_effect = Exception("Sanctions API Down")
        mock_pep.check_entity_pep.return_value = [{"name": "Mr. PEP"}]
        mock_news_client = mock_news.return_value
        mock_news_client.get_everything.return_value = {"status": "ok", "articles": []}
        
        # Mock for the metrics counter
        mock_metrics_counter = MagicMock()
        mock_metrics_label = MagicMock()
        mock_metrics_counter.labels = MagicMock(return_value=mock_metrics_label)
        
        aggregator = mlint_intel.IntelligenceAggregator(
            sanctions_client=mock_sanctions,
            ubo_client=mock_ubo,
            chain_client=mock_chain,
            pep_client=mock_pep,
            metrics_api_failures=mock_metrics_counter # Pass in the mock counter
        )
        
        entity = Entity(name="Test Entity", entity_type=EntityType.PERSON)
        
        # Run the aggregator
        results = await aggregator.gather_entity_intelligence(entity)
        
        # 1. Check that the error was caught and recorded
        assert "error" in results["sanctions"]
        assert "Sanctions API Down" in results["sanctions"]["error"]
        
        # 2. Check that other tasks *succeeded*
        assert "error" not in results["pep_screening"]
        assert results["pep_screening"][0]["name"] == "Mr. PEP"
        
        # 3. Check that the failure metric was called correctly
        mock_metrics_counter.labels.assert_called_with(source="sanctions")
        mock_metrics_label.inc.assert_called_once()


# --- `mlint_ai.py` Tests (Real AI & Graph) ---

class TestMLintAI:

    @patch("chimera_intel.core.mlint_ai.pipeline")
    def test_get_nlp_classifier_caching(self, mock_pipeline):
        """Tests the model caching logic in the 'get' functions."""
        mock_pipeline.return_value = "my-mocked-model"
        
        # Clear cache for test
        mlint_ai._nlp_classifier = None
        
        # First call: loads model
        model1 = mlint_ai.get_nlp_classifier()
        assert model1 == "my-mocked-model"
        mock_pipeline.assert_called_once()
        
        # Second call: uses cache
        model2 = mlint_ai.get_nlp_classifier()
        assert model2 == "my-mocked-model"
        mock_pipeline.assert_called_once() # Still only called once

    @patch("chimera_intel.core.mlint_ai.get_nlp_classifier")
    async def test_classify_adverse_media_ai(self, mock_get_classifier):
        """Tests the classification logic and confidence threshold."""
        
        # Mock the pipeline result
        mock_pipeline_instance = MagicMock(return_value={
            "labels": ["Fraud", "Money Laundering", "Sanctions"],
            "scores": [0.9, 0.8, 0.1] # High, High, Low
        })
        mock_get_classifier.return_value = mock_pipeline_instance
        
        categories = await mlint_ai.classify_adverse_media_ai("test text")
        
        assert "Fraud" in categories
        assert "Money Laundering" in categories
        assert "Sanctions" not in categories # Below 0.7 threshold

    @patch("chimera_intel.core.mlint_ai.GraphAnalyzer", new_callable=AsyncMock)
    async def test_run_gnn_anomaly_detection(self, mock_graph_analyzer_class):
        """Tests that the GNN function correctly calls the GraphAnalyzer."""
        
        # Mock the instance methods
        mock_instance = mock_graph_analyzer_class.return_value
        mock_instance.run_pagerank_anomaly = AsyncMock(return_value=[
            GnnAnomalyResult(node_id="acct:123", node_type="Account", score=9.5, reason="High PageRank")
        ])
        mock_instance.close = AsyncMock()
        
        results = await mlint_ai.run_gnn_anomaly_detection()
        
        # 1. Assert the class was instantiated
        mock_graph_analyzer_class.assert_called_once()
        # 2. Assert PageRank was called
        mock_instance.run_pagerank_anomaly.assert_called_once()
        # 3. Assert the connection was closed
        mock_instance.close.assert_called_once()
        # 4. Assert results are passed through
        assert len(results) == 1
        assert results[0].node_id == "acct:123"


# --- `mlint_graph.py` Tests (Task 3) ---

class TestMLintGraph:

    async def test_add_transactions_batch(self, mock_neo4j_driver):
        """Tests the UNWIND batch query formation (Task 3)."""
        graph = mlint_graph.GraphAnalyzer()
        
        txs = [
            Transaction(tx_id="t1", from_entity="acct:A", to_entity="acct:B", amount=100, currency="USD", timestamp=datetime.now()),
            Transaction(tx_id="t2", from_entity="acct:C", to_entity="acct:D", amount=200, currency="USD", timestamp=datetime.now())
        ]
        
        await graph.add_transactions_batch(txs)
        
        # Get the mock session
        mock_session = mock_neo4j_driver.session.return_value.__aenter__.return_value
        
        # 1. Assert 'run' was called
        mock_session.run.assert_called_once()
        
        # 2. Check the query parameters
        call_args = mock_session.run.call_args
        query_text = call_args[0][0]
        query_params = call_args[0][1]
        
        assert "UNWIND $txs_batch as tx" in query_text
        assert "txs_batch" in query_params
        assert len(query_params["txs_batch"]) == 2
        assert query_params["txs_batch"][0]["tx_id"] == "t1"
        assert query_params["txs_batch"][1]["tx_id"] == "t2"
        assert query_params["txs_batch"][0]["from_type"] == "acct"
        
        await graph.close() # Test close

    async def test_run_pagerank_anomaly(self, mock_neo4j_driver):
        """Tests the GDS PageRank execution flow."""
        graph = mlint_graph.GraphAnalyzer()
        
        # Mock the session and its results
        mock_session = mock_neo4j_driver.session.return_value.__aenter__.return_value
        
        # Mock the result of the PageRank query
        mock_pagerank_result = [
            MagicMock(data={"entityId": "acct:A", "entityType": "Account", "score": 10.1}),
            MagicMock(data={"entityId": "acct:B", "entityType": "Account", "score": 9.2})
        ]
        
        # Set up the mock 'run' to return an async iterator
        async def async_iter(results):
            for res in results:
                yield res
                
        mock_session.run.return_value = async_iter(mock_pagerank_result)

        results = await graph.run_pagerank_anomaly()

        # Check results
        assert len(results) == 2
        assert results[0].node_id == "acct:A"
        assert results[0].score == 10.1
        
        # Check that all GDS queries were called
        call_args_list = mock_session.run.call_args_list
        assert len(call_args_list) == 4
        assert "CALL gds.graph.drop('entity-transactions')" in call_args_list[0][0][0] # First call (cleanup)
        assert "CALL gds.graph.project" in call_args_list[1][0][0] # Second call (project)
        assert "CALL gds.pageRank.stream" in call_args_list[2][0][0] # Third call (run)
        assert "CALL gds.graph.drop('entity-transactions')" in call_args_list[3][0][0] # Fourth call (cleanup)
        
        await graph.close()