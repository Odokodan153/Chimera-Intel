import unittest
import json
import tempfile
import os
import anyio
import httpx
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner
from datetime import date

# Import the app and all functions/schemas to be tested
from chimera_intel.core.mlint import (
    mlint_app,
    analyze_transactions,
    analyze_entity_risk,
    get_jurisdiction_risk,
    get_ubo_data,
    check_crypto_wallet,
    export_entity_to_stix,
)
from chimera_intel.core.schemas import (
    EntityRiskResult,
    CryptoWalletScreenResult,
    Transaction,
    TransactionAnalysisResult,
    SwiftTransactionAnalysisResult,
    UboResult,
    UboData,
    GnnAnomalyResult,
)

runner = CliRunner()


class TestMlint(unittest.TestCase):
    """
    Test cases for the advanced, scalable MLINT module (v2).
    """

    # --- Core Function Tests ---

    def test_get_jurisdiction_risk_lists(self):
        """Tests all three risk levels for jurisdictions."""
        # High Risk
        high = get_jurisdiction_risk("North Korea")
        self.assertEqual(high.risk_level, "High")
        self.assertTrue(high.is_fatf_black_list)
        self.assertEqual(high.risk_score, 90)
        
        # Medium Risk
        med = get_jurisdiction_risk("Panama")
        self.assertEqual(med.risk_level, "Medium")
        self.assertTrue(med.is_fatf_grey_list)
        self.assertEqual(med.risk_score, 60)
        
        # Low Risk
        low = get_jurisdiction_risk("Canada")
        self.assertEqual(low.risk_level, "Low")
        self.assertFalse(low.is_fatf_black_list)
        self.assertEqual(low.risk_score, 10)

    @patch("chimera_intel.core.mlint.API_KEYS")
    @patch("chimera_intel.core.mlint.get_ubo_data", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint.httpx.AsyncClient")
    def test_analyze_entity_risk_async(self, mock_async_client, mock_get_ubo, mock_api_keys):
        """Tests the async risk scoring logic, including UBO call."""
        # Arrange
        mock_api_keys.aml_api_key = "fake_key"
        
        # Mock the UBO call
        mock_get_ubo.return_value = UboResult(
            company_name="RiskyCo",
            ultimate_beneficial_owners=[
                UboData(name="Mr. PEP", ownership_percentage=50.0, is_pep=True)
            ]
        )
        
        # Mock the httpx (AML/Sanctions) call
        # We still use mock logic inside the function, so just mock the sleep
        with patch("chimera_intel.core.mlint.anyio.sleep", new_callable=AsyncMock):
            # Act
            result = anyio.run(analyze_entity_risk, "RiskyCo", "Panama")

        # Assert
        self.assertIsNone(result.error)
        self.assertGreater(result.risk_score, 50) # (Grey List + UBO PEP + Sanctions)
        self.assertEqual(result.pep_links, 3) # 1 from UBO, 2 from (mocked) API
        self.assertEqual(result.sanctions_hits, 1)
        self.assertIn("FATF Grey List", result.risk_factors[0])
        self.assertIn("UBO link to PEP: Mr. PEP", result.risk_factors[1])

    def test_analyze_transactions_batch_deprecation(self):
        """
        Tests the deprecated batch transaction analysis.
        Ensures it uses Dask/ML but correctly skips Neo4j cycle detection.
        """
        txns = [
            # Anomaly
            Transaction(id="t1", date=date(2023, 1, 1), amount=1000000, currency="USD", sender_id="A", receiver_id="B", sender_jurisdiction="USA", receiver_jurisdiction="IRAN"),
            # Normal
            Transaction(id="t2", date=date(2023, 1, 1), amount=500, currency="USD", sender_id="C", receiver_id="D", sender_jurisdiction="USA", receiver_jurisdiction="USA"),
            # Round-trip (should be ignored by this function)
            Transaction(id="t3", date=date(2023, 1, 1), amount=50000, currency="USD", sender_id="E", receiver_id="F", sender_jurisdiction="USA", receiver_jurisdiction="USA"),
            Transaction(id="t4", date=date(2023, 1, 2), amount=50000, currency="USD", sender_id="F", receiver_id="E", sender_jurisdiction="USA", receiver_jurisdiction="USA"),
        ]
        
        result = analyze_transactions(txns)

        # Assert ML Anomaly score was calculated
        self.assertIsNone(result.error)
        self.assertGreater(result.anomaly_score, 0)
        self.assertIn("receiver_jurisdiction_risk", result.anomaly_features_used)
        
        # Assert Cycle detection was SKIPPED
        self.assertEqual(len(result.round_tripping_alerts), 0)

    # --- [NEW] Core Async Function Unit Tests ---

    @patch("chimera_intel.core.mlint.MLINT_AML_API_URL", "http://fake-ubo-api.com")
    @patch("chimera_intel.core.mlint.API_KEYS")
    @patch("chimera_intel.core.mlint.httpx.AsyncClient")
    def test_get_ubo_data_success(self, mock_async_client, mock_api_keys):
        """Tests the UBO data function directly with a mocked successful API response."""
        # Arrange
        mock_api_keys.open_corporates_api_key = "fake_ubo_key"
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "ultimate_beneficial_owners": [
                {"name": "Owner One", "ownership_percentage": 75.0, "is_pep": True}
            ],
            "corporate_structure": {"type": "LLC"}
        }
        mock_async_client.return_value.__aenter__.return_value.get.return_value = mock_response

        # Act
        result = anyio.run(get_ubo_data, "TestCo")

        # Assert
        self.assertIsNone(result.error)
        self.assertEqual(result.company_name, "TestCo")
        self.assertEqual(len(result.ultimate_beneficial_owners), 1)
        self.assertEqual(result.ultimate_beneficial_owners[0].name, "Owner One")
        self.assertTrue(result.ultimate_beneficial_owners[0].is_pep)

    @patch("chimera_intel.core.mlint.API_KEYS")
    def test_get_ubo_data_no_key(self, mock_api_keys):
        """Tests that get_ubo_data fails gracefully without an API key."""
        mock_api_keys.open_corporates_api_key = None
        mock_api_keys.world_check_api_key = None
        
        result = anyio.run(get_ubo_data, "TestCo")
        
        self.assertIsNotNone(result.error)
        self.assertIn("No UBO API key", result.error)

    @patch("chimera_intel.core.mlint.MLINT_AML_API_URL", "http://fake-ubo-api.com")
    @patch("chimera_intel.core.mlint.API_KEYS")
    @patch("chimera_intel.core.mlint.httpx.AsyncClient")
    def test_get_ubo_data_http_error(self, mock_async_client, mock_api_keys):
        """Tests that get_ubo_data handles an httpx.RequestError."""
        mock_api_keys.open_corporates_api_key = "fake_ubo_key"
        mock_async_client.return_value.__aenter__.return_value.get.side_effect = httpx.RequestError("Mock network error", request=None)

        result = anyio.run(get_ubo_data, "TestCo")

        self.assertIsNotNone(result.error)
        self.assertIn("API request error", result.error)

    @patch("chimera_intel.core.mlint.MLINT_CHAIN_API_URL", "http://fake-chain-api.com")
    @patch("chimera_intel.core.mlint.API_KEYS")
    @patch("chimera_intel.core.mlint.httpx.AsyncClient")
    def test_check_crypto_wallet_success(self, mock_async_client, mock_api_keys):
        """Tests the check_crypto_wallet function directly with a mocked successful API response."""
        mock_api_keys.chain_api_key = "fake_chain_key"
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "risk_score": 95,
            "associations": ["Darknet Market"],
            "mixer_interaction": True
        }
        mock_async_client.return_value.__aenter__.return_value.get.return_value = mock_response

        result = anyio.run(check_crypto_wallet, "123_bad_address")

        self.assertIsNone(result.error)
        self.assertEqual(result.risk_level, "High")
        self.assertEqual(result.risk_score, 95)
        self.assertTrue(result.mixer_interaction)
        self.assertIn("Darknet Market", result.known_associations)

    @patch("chimera_intel.core.mlint.API_KEYS")
    def test_check_crypto_wallet_no_key(self, mock_api_keys):
        """Tests that check_crypto_wallet fails gracefully without an API key."""
        mock_api_keys.chainalysis_api_key = None
        mock_api_keys.trm_labs_api_key = None
        mock_api_keys.chain_api_key = None
        
        result = anyio.run(check_crypto_wallet, "123_bad_address")
        
        self.assertIsNotNone(result.error)
        self.assertIn("No Crypto analytics API key", result.error)

    # --- [NEW] STIX Export Test ---
    
    def test_export_entity_to_stix(self):
        """Tests the generation of a STIX 2.1 bundle from an EntityRiskResult."""
        # Arrange
        entity_result = EntityRiskResult(
            company_name="STIX TestCo",
            jurisdiction="Panama",
            risk_score=85,
            risk_factors=["FATF Grey List", "3 PEP Links"],
            pep_links=3,
            sanctions_hits=1
        )
        
        # Act
        stix_bundle_str = export_entity_to_stix(entity_result)
        stix_bundle = json.loads(stix_bundle_str)
        
        # Assert
        self.assertEqual(stix_bundle["type"], "bundle")
        self.assertEqual(len(stix_bundle["objects"]), 3)
        
        # Find and validate the objects
        identity = next(obj for obj in stix_bundle["objects"] if obj["type"] == "identity")
        indicator = next(obj for obj in stix_bundle["objects"] if obj["type"] == "indicator")
        relationship = next(obj for obj in stix_bundle["objects"] if obj["type"] == "relationship")

        self.assertEqual(identity["name"], "STIX TestCo")
        self.assertEqual(indicator["confidence"], 85)
        self.assertIn("High ML risk: STIX TestCo", indicator["description"])
        self.assertEqual(relationship["relationship_type"], "indicates")
        self.assertEqual(relationship["source_ref"], indicator["id"])
        self.assertEqual(relationship["target_ref"], identity["id"])

    # --- CLI Command Tests (Updated) ---

    @patch("chimera_intel.core.mlint.analyze_entity_risk", new_callable=AsyncMock)
    def test_cli_check_entity_with_outputs(self, mock_analyze_entity):
        """
        Tests the 'check-entity' command, now including --output and --stix-out flags.
        """
        # Arrange
        mock_analyze_entity.return_value = EntityRiskResult(
            company_name="TestCo",
            jurisdiction="Panama",
            risk_score=70,
            risk_factors=["FATF Grey List", "1 PEP Link"],
        )
        
        with tempfile.NamedTemporaryFile(mode='w', delete=True, suffix=".json") as tmp_out, \
             tempfile.NamedTemporaryFile(mode='w', delete=True, suffix=".json") as tmp_stix:
            
            # Act
            result = runner.invoke(
                mlint_app,
                [
                    "check-entity",
                    "--company-name", "TestCo",
                    "--jurisdiction", "Panama",
                    "--output", tmp_out.name,
                    "--stix-out", tmp_stix.name,
                ],
            )

            # Assert
            self.assertEqual(result.exit_code, 0, msg=result.output)
            mock_analyze_entity.assert_called_with("TestCo", "Panama")
            self.assertIn("Entity Risk Report for TestCo", result.stdout)
            self.assertIn("Risk Score: 70 / 100", result.stdout)
            
            # Assert file outputs
            with open(tmp_out.name, 'r') as f:
                json_data = json.load(f)
                self.assertEqual(json_data["company_name"], "TestCo")
                self.assertEqual(json_data["risk_score"], 70)

            with open(tmp_stix.name, 'r') as f:
                stix_data = json.load(f)
                self.assertEqual(stix_data["type"], "bundle")
                self.assertEqual(stix_data["objects"][0]["name"], "TestCo")

    @patch("chimera_intel.core.mlint.check_crypto_wallet", new_callable=AsyncMock)
    def test_cli_check_wallet_with_output(self, mock_check_wallet):
        """Tests the 'check-wallet' command, now including --output flag."""
        # Arrange
        mock_check_wallet.return_value = CryptoWalletScreenResult(
            wallet_address="123_bad_address",
            risk_level="High",
            risk_score=95,
            mixer_interaction=True
        )

        with tempfile.NamedTemporaryFile(mode='w', delete=True, suffix=".json") as tmp_out:
            # Act
            result = runner.invoke(
                mlint_app,
                ["check-wallet", "--address", "123_bad_address", "--output", tmp_out.name]
            )
            
            # Assert
            self.assertEqual(result.exit_code, 0, msg=result.output)
            mock_check_wallet.assert_called_with("123_bad_address")
            self.assertIn("Wallet Screening", result.stdout)
            self.assertIn("High", result.stdout)
            
            # Assert file output
            with open(tmp_out.name, 'r') as f:
                json_data = json.load(f)
                self.assertEqual(json_data["wallet_address"], "123_bad_address")
                self.assertEqual(json_data["risk_score"], 95)

    @patch("chimera_intel.core.mlint.analyze_transactions")
    def test_cli_analyze_tx_batch_with_outputs(self, mock_analyze_tx):
        """Tests the 'analyze-tx-batch' command, now including --output and --graph-out flags."""
        # Arrange
        mock_analyze_tx.return_value = TransactionAnalysisResult(
            total_transactions=10,
            total_volume=100000,
            anomaly_score=10.0,
            anomaly_features_used=['amount']
        )
        
        mock_tx_data = [{"id": "t1", "date": "2023-01-01", "amount": 50000, "currency": "USD", "sender_id": "A", "receiver_id": "B"}]
        
        with tempfile.NamedTemporaryFile(mode='w', delete=True, suffix=".json") as tmp_in, \
             tempfile.NamedTemporaryFile(mode='w', delete=True, suffix=".json") as tmp_out, \
             tempfile.NamedTemporaryFile(mode='w', delete=True, suffix=".html") as tmp_graph:
            
            json.dump(mock_tx_data, tmp_in)
            tmp_in.flush()

            # Act
            result = runner.invoke(
                mlint_app,
                [
                    "analyze-tx-batch", tmp_in.name,
                    "--output", tmp_out.name,
                    "--graph-out", tmp_graph.name
                ]
            )
            
            # Assert
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertIn("Transaction Analysis Report", result.stdout)
            self.assertIn("ML Anomaly Score: 10.00%", result.stdout)
            self.assertIn("Interactive graph visualization saved to", result.stdout)

            # Assert file outputs
            with open(tmp_out.name, 'r') as f:
                json_data = json.load(f)
                self.assertEqual(json_data["total_transactions"], 10)
                self.assertEqual(json_data["anomaly_score"], 10.0)

            self.assertTrue(os.path.exists(tmp_graph.name))
            self.assertGreater(os.path.getsize(tmp_graph.name), 0)


    @patch("chimera_intel.core.mlint.API_KEYS")
    @patch("chimera_intel.core.mlint.GraphDatabase.driver")
    def test_cli_graph_find_cycles(self, mock_neo4j_driver, mock_api_keys):
        """Tests the new 'graph find-cycles' command."""
        # Arrange
        mock_api_keys.neo4j_uri = "bolt://localhost:7687"
        mock_api_keys.neo4j_user = "neo4j"
        mock_api_keys.neo4j_password = "password"
        
        # Mock the Neo4j session and result
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.data.return_value = [
            {"cycle": ["A", "B", "C", "A"], "length": 3}
        ]
        # This is how you mock a context manager (the `with` statement)
        mock_session.__enter__.return_value.run.return_value = mock_result
        mock_driver.session.return_value = mock_session
        mock_neo4j_driver.return_value = mock_driver

        # Act
        result = runner.invoke(mlint_app, ["graph", "find-cycles", "--max-length", "3"])
        
        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        mock_neo4j_driver.assert_called_with("bolt://localhost:7687", auth=("neo4j", "password"))
        self.assertIn("Successfully ran query. Found 1 cycles.", result.stdout)
        self.assertIn("Cycle: A -> B -> C -> A", result.stdout)
    
    @patch("chimera_intel.core.mlint.API_KEYS")
    def test_cli_graph_missing_creds(self, mock_api_keys):
        """Tests that graph commands fail without credentials."""
        # Arrange
        mock_api_keys.neo4j_uri = None # Missing
        
        # Act
        result = runner.invoke(mlint_app, ["graph", "find-cycles"])
        
        # Assert
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Error: Neo4j credentials", result.stdout)

    @patch("chimera_intel.core.mlint.API_KEYS")
    @patch("chimera_intel.core.mlint.KafkaConsumer")
    def test_cli_stream_start_consumer(self, mock_kafka_consumer, mock_api_keys):
        """Tests the new 'stream start-consumer' command."""
        # Arrange
        mock_api_keys.kafka_bootstrap_servers = "kafka:9092"
        mock_api_keys.kafka_topic_transactions = "txns"
        mock_api_keys.kafka_consumer_group = "mlint-test"
        
        # Mock the KafkaConsumer to return one message and then stop
        mock_message = MagicMock()
        mock_message.value = {"id": "tx-123", "sender_id": "A", "receiver_id": "B", "amount": 9500, "currency": "USD", "sender_jurisdiction": "USA", "receiver_jurisdiction": "PA"}
        
        mock_consumer_instance = MagicMock()
        mock_consumer_instance.__iter__.return_value = iter([mock_message, KeyboardInterrupt()])
        mock_kafka_consumer.return_value = mock_consumer_instance

        # Act
        result = runner.invoke(mlint_app, ["stream", "start-consumer"])
        
        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        mock_kafka_consumer.assert_called_with(
            "txns",
            bootstrap_servers=["kafka:9092"],
            auto_offset_reset='earliest',
            group_id='mlint-test',
            value_deserializer=unittest.mock.ANY
        )
        # Check that our mock message was processed
        self.assertIn("Received Transaction tx-123", result.stdout)
        self.assertIn("Alerts:", result.stdout)
        self.assertIn("Potential Structuring", result.stdout)
        self.assertIn("Shutting down Kafka consumer", result.stdout)

    # --- [NEW] Additional CLI Tests for Gaps ---

    @patch("chimera_intel.core.mlint.analyze_transactions")
    def test_cli_analyze_swift_mt103(self, mock_analyze_tx):
        """Tests the 'analyze-swift-mt103' command for parsing and execution."""
        # Arrange
        # A minimal valid MT103 message
        swift_message = """
{1:F01YOURCODEHV0AXXX0000000000}
{2:I103SENDERBICHXXXXN}
{3:{108:MT103}}
{4:
:20:TX-REF-12345
:32A:231030USD12500,
:50K:/12345678
Sender Name
Sender Address
:53A:SNDRBICXXXX
:57A:RCVRBICXXXX
:59:/87654321
Receiver Name
Receiver Address
:71A:OUR
-}
"""
        mock_analyze_tx.return_value = TransactionAnalysisResult(
            total_transactions=1,
            anomaly_score=5.0,
            anomaly_features_used=['amount']
        )
        
        with tempfile.NamedTemporaryFile(mode='w', delete=True, suffix=".txt") as tmp_swift, \
             tempfile.NamedTemporaryFile(mode='w', delete=True, suffix=".json") as tmp_out:
            
            tmp_swift.write(swift_message)
            tmp_swift.flush()
            
            # Act
            result = runner.invoke(
                mlint_app,
                ["analyze-swift-mt103", tmp_swift.name, "--output", tmp_out.name]
            )
            
            # Assert
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertIn("Successfully parsed MT103 (Ref: TX-REF-12345)", result.stdout)
            
            # Check that analyze_transactions was called with the parsed transaction
            mock_analyze_tx.assert_called_once()
            called_tx_list = mock_analyze_tx.call_args[0][0]
            self.assertEqual(len(called_tx_list), 1)
            self.assertEqual(called_tx_list[0].id, "TX-REF-12345")
            self.assertEqual(called_tx_list[0].amount, 12500.0)
            self.assertEqual(called_tx_list[0].sender_jurisdiction, "HV") # From Block 1
            self.assertEqual(called_tx_list[0].receiver_jurisdiction, "IC") # From :57A:

            # Check output file
            with open(tmp_out.name, 'r') as f:
                json_data = json.load(f)
                self.assertEqual(json_data["transaction"]["id"], "TX-REF-12345")
                self.assertEqual(json_data["analysis"]["anomaly_score"], 5.0)

    @patch("chimera_intel.core.mlint.API_KEYS")
    def test_cli_stream_missing_creds(self, mock_api_keys):
        """Tests that 'stream start-consumer' fails without credentials."""
        # Arrange
        mock_api_keys.kafka_bootstrap_servers = None
        mock_api_keys.kafka_topic_transactions = None
        mock_api_keys.kafka_consumer_group = None
        
        # Act
        result = runner.invoke(mlint_app, ["stream", "start-consumer"])
        
        # Assert
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Error: Kafka settings", result.stdout)

    def test_cli_graph_run_gnn_anomaly(self):
        """Tests the placeholder 'graph run-gnn-anomaly' command."""
        # Act
        result = runner.invoke(mlint_app, ["graph", "run-gnn-anomaly"])
        
        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("This is a placeholder for a complex GNN task", result.stdout)
        self.assertIn("GnnAnomalyResult", result.stdout)


if __name__ == "__main__":
    unittest.main()