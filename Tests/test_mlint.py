# Chimera-Intel/Tests/test_mlint.py
import unittest
import json
import tempfile
import os
import anyio
import httpx
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner
from datetime import date
import pandas as pd

# Import the app and all functions/schemas to be tested
from chimera_intel.core.mlint import (
    mlint_app,
    analyze_transactions,
    analyze_entity_risk,
    get_jurisdiction_risk,
    get_ubo_data,
    check_crypto_wallet,
    export_entity_to_stix,
    # --- [MLINT 2.0] New Imports ---
    resolve_entities,
    correlate_trade_payment,
    detect_graph_anomalies
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
    # --- [MLINT 2.0] New Schemas ---
    EntityLink,
    EntityResolutionResult,
    TradeData,
    PaymentData,
    TradeCorrelationResult
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

    @patch("chimera_intel.core.mlint.MLINT_AML_API_URL", "http://fake-api.com")
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
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "pep_links": 2,
            "sanctions_hits": 1,
            "adverse_media_hits": 10,
            "shell_indicators": ["High-risk nominee director"]
        }
        mock_async_client.return_value.__aenter__.return_value.get.return_value = mock_response

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
            Transaction(id="t1", date=date(2023, 1, 1), amount=1000000, currency="USD", sender_id="A", receiver_id="B", sender_jurisdiction="USA", receiver_jurisdiction="IRAN"),
            Transaction(id="t2", date=date(2023, 1, 1), amount=500, currency="USD", sender_id="C", receiver_id="D", sender_jurisdiction="USA", receiver_jurisdiction="USA"),
            Transaction(id="t3", date=date(2023, 1, 1), amount=50000, currency="USD", sender_id="E", receiver_id="F", sender_jurisdiction="USA", receiver_jurisdiction="USA"),
            Transaction(id="t4", date=date(2023, 1, 2), amount=50000, currency="USD", sender_id="F", receiver_id="E", sender_jurisdiction="USA", receiver_jurisdiction="USA"),
        ]
        
        result = analyze_transactions(txns)

        self.assertIsNone(result.error)
        self.assertGreater(result.anomaly_score, 0)
        self.assertIn("receiver_jurisdiction_risk", result.anomaly_features_used)
        self.assertEqual(len(result.round_tripping_alerts), 0)

    # --- [NEW] Core Async Function Unit Tests ---

    @patch("chimera_intel.core.mlint.MLINT_AML_API_URL", "http://fake-ubo-api.com")
    @patch("chimera_intel.core.mlint.API_KEYS")
    @patch("chimera_intel.core.mlint.httpx.AsyncClient")
    def test_get_ubo_data_success(self, mock_async_client, mock_api_keys):
        """Tests the UBO data function directly with a mocked successful API response."""
        mock_api_keys.open_corporates_api_key = "fake_ubo_key"
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "ultimate_beneficial_owners": [
                {"name": "Owner One", "ownership_percentage": 75.0, "is_pep": True}
            ],
            "corporate_structure": {"type": "LLC"}
        }
        mock_async_client.return_value.__aenter__.return_value.get.return_value = mock_response

        result = anyio.run(get_ubo_data, "TestCo")

        self.assertIsNone(result.error)
        self.assertEqual(result.company_name, "TestCo")
        self.assertEqual(len(result.ultimate_beneficial_owners), 1)
        self.assertEqual(result.ultimate_beneficial_owners[0].name, "Owner One")

    @patch("chimera_intel.core.mlint.API_KEYS")
    def test_get_ubo_data_no_key(self, mock_api_keys):
        """Tests that get_ubo_data fails gracefully without an API key."""
        mock_api_keys.open_corporates_api_key = None
        mock_api_keys.world_check_api_key = None
        
        result = anyio.run(get_ubo_data, "TestCo")
        self.assertIn("No UBO API key", result.error)

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
        self.assertTrue(result.mixer_interaction)

    # --- [MLINT 2.0] New Function Tests ---

    @patch("chimera_intel.core.mlint.check_crypto_wallet", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint.get_neo4j_driver")
    def test_resolve_entities_success(self, mock_get_driver, mock_check_wallet):
        """[MLINT 2.0] Tests the new entity resolution function."""
        # Arrange
        # 1. Mock Neo4j
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_result = [
            {
                "e1_type": "Company", "e1_id": "TestCo",
                "relationship": "HAS_UBO",
                "e2_type": "Person", "e2_id": "John Doe"
            },
            {
                "e1_type": "Person", "e1_id": "John Doe",
                "relationship": "OWNS_WALLET",
                "e2_type": "Wallet", "e2_id": "123-wallet"
            },
        ]
        mock_session.run.return_value = mock_result
        mock_driver.session.return_value = mock_session
        mock_get_driver.return_value = mock_driver
        
        # 2. Mock Wallet Check (for MVP features)
        mock_check_wallet.return_value = CryptoWalletScreenResult(
            wallet_address="123-wallet", risk_score=90,
            mixer_interaction=True, sanctioned_entity_link=False
        )

        # Act
        result = anyio.run(
            resolve_entities,
            company_names=["TestCo"],
            wallet_addresses=["123-wallet"],
            person_names=["John Doe"]
        )

        # Assert
        self.assertIsNone(result.error)
        self.assertEqual(result.total_entities_found, 4) # TestCo, John Doe, 123-wallet, Mixer
        
        # Check graph links
        link_descs = [l.description for l in result.links]
        self.assertIn("Found graph link: Company:TestCo -> HAS_UBO -> Person:John Doe", link_descs)
        self.assertIn("Found graph link: Person:John Doe -> OWNS_WALLET -> Wallet:123-wallet", link_descs)
        
        # Check MVP wallet link
        self.assertIn("Wallet has interacted with a known mixer.", link_descs)
        self.assertNotIn("Wallet has links to a sanctioned entity.", link_descs)

    @patch("chimera_intel.core.mlint.MLINT_TRADE_API_URL", "http://fake-trade-api.com")
    @patch("chimera_intel.core.mlint.MLINT_AML_API_URL", "http://fake-payment-api.com")
    @patch("chimera_intel.core.mlint.API_KEYS")
    @patch("chimera_intel.core.mlint.httpx.AsyncClient")
    def test_correlate_trade_payment_success(self, mock_async_client, mock_api_keys):
        """[MLINT 2.0] Tests the new trade/payment correlation function."""
        # Arrange
        mock_api_keys.trade_api_key = "fake_trade_key"
        mock_api_keys.aml_api_key = "fake_payment_key"
        
        # Mock Trade API Response
        mock_trade_response = MagicMock()
        mock_trade_response.raise_for_status = MagicMock()
        mock_trade_response.json.return_value = {
            "document_id": "BOL-123", "invoice_amount": 50000.00,
            "exporter_name": "Global Exporters Inc", "importer_name": "Local Importers Ltd"
        }
        
        # Mock Payment API Response
        mock_payment_response = MagicMock()
        mock_payment_response.raise_for_status = MagicMock()
        mock_payment_response.json.return_value = {
            "payment_id": "SWIFT-456", "amount": 50000.00,
            "sender_name": "Global Exporters Inc (Acme)", "receiver_name": "Local Importers Ltd"
        }
        
        # Set client to return different mocks based on URL
        mock_client_instance = MagicMock()
        mock_client_instance.get.side_effect = [
            mock_trade_response, # First call
            mock_payment_response # Second call
        ]
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance

        # Act
        result = anyio.run(correlate_trade_payment, "SWIFT-456", "BOL-123")
        
        # Assert
        self.assertIsNone(result.error)
        self.assertTrue(result.is_correlated)
        self.assertEqual(result.confidence, "High")
        self.assertEqual(result.correlation_score, 1.0)
        self.assertEqual(len(result.mismatches), 0)
        self.assertEqual(result.payment.amount, 50000.00)
        self.assertEqual(result.trade_document.exporter_name, "Global Exporters Inc")

    # --- STIX Export Test ---
    
    def test_export_entity_to_stix(self):
        """Tests the generation of a STIX 2.1 bundle from an EntityRiskResult."""
        entity_result = EntityRiskResult(
            company_name="STIX TestCo", jurisdiction="Panama",
            risk_score=85, risk_factors=["FATF Grey List", "3 PEP Links"],
            pep_links=3, sanctions_hits=1
        )
        stix_bundle_str = export_entity_to_stix(entity_result)
        stix_bundle = json.loads(stix_bundle_str)
        
        self.assertEqual(stix_bundle["type"], "bundle")
        identity = next(obj for obj in stix_bundle["objects"] if obj["type"] == "identity")
        indicator = next(obj for obj in stix_bundle["objects"] if obj["type"] == "indicator")
        self.assertEqual(identity["name"], "STIX TestCo")
        self.assertEqual(indicator["confidence"], 85)

    # --- CLI Command Tests (Updated) ---

    @patch("chimera_intel.core.mlint.analyze_entity_risk", new_callable=AsyncMock)
    def test_cli_check_entity_with_outputs(self, mock_analyze_entity):
        """Tests the 'check-entity' command, including --output and --stix-out flags."""
        mock_analyze_entity.return_value = EntityRiskResult(
            company_name="TestCo", jurisdiction="Panama",
            risk_score=70, risk_factors=["FATF Grey List", "1 PEP Link"],
        )
        
        with tempfile.NamedTemporaryFile(mode='w', delete=True, suffix=".json") as tmp_out, \
             tempfile.NamedTemporaryFile(mode='w', delete=True, suffix=".json") as tmp_stix:
            
            result = runner.invoke(
                mlint_app,
                [
                    "check-entity", "--company-name", "TestCo", "--jurisdiction", "Panama",
                    "--output", tmp_out.name, "--stix-out", tmp_stix.name,
                ],
            )

            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertIn("Entity Risk Report for TestCo", result.stdout)
            
            with open(tmp_out.name, 'r') as f:
                self.assertEqual(json.load(f)["company_name"], "TestCo")
            with open(tmp_stix.name, 'r') as f:
                self.assertEqual(json.load(f)["type"], "bundle")

    @patch("chimera_intel.core.mlint.check_crypto_wallet", new_callable=AsyncMock)
    def test_cli_check_wallet_with_output(self, mock_check_wallet):
        """Tests the 'check-wallet' command, including --output flag."""
        mock_check_wallet.return_value = CryptoWalletScreenResult(
            wallet_address="123_bad_address", risk_level="High",
            risk_score=95, mixer_interaction=True
        )

        with tempfile.NamedTemporaryFile(mode='w', delete=True, suffix=".json") as tmp_out:
            result = runner.invoke(
                mlint_app,
                ["check-wallet", "--address", "123_bad_address", "--output", tmp_out.name]
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertIn("Wallet Screening", result.stdout)
            with open(tmp_out.name, 'r') as f:
                self.assertEqual(json.load(f)["risk_score"], 95)

    # --- [MLINT 2.0] New CLI Tests ---

    @patch("chimera_intel.core.mlint.resolve_entities", new_callable=AsyncMock)
    def test_cli_resolve(self, mock_resolve):
        """[MLINT 2.0] Tests the new 'mlint resolve' command."""
        # Arrange
        mock_resolve.return_value = EntityResolutionResult(
            total_entities_found=3,
            links=[EntityLink(
                source="Wallet:123", target="Entity:Mixer",
                type="INTERACTED_WITH", description="Wallet has interacted with a known mixer."
            )]
        )
        
        # Act
        result = runner.invoke(mlint_app, ["resolve", "--wallet", "123"])
        
        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        mock_resolve.assert_called_with([], ["123"], [])
        self.assertIn("Entity Resolution Report", result.stdout)
        self.assertIn("Total Unique Entities Found: 3", result.stdout)
        self.assertIn("Wallet:123 --(INTERACTED_WITH)--> Entity:Mixer", result.stdout)

    @patch("chimera_intel.core.mlint.correlate_trade_payment", new_callable=AsyncMock)
    def test_cli_correlate_trade(self, mock_correlate):
        """[MLINT 2.0] Tests the new 'mlint correlate-trade' command."""
        # Arrange
        mock_correlate.return_value = TradeCorrelationResult(
            is_correlated=False,
            confidence="Low",
            mismatches=["Amount mismatch: Payment=500, Invoice=5000"]
        )
        
        # Act
        result = runner.invoke(mlint_app, ["correlate-trade", "--payment-id", "P-1", "--trade-doc-id", "T-1"])
        
        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        mock_correlate.assert_called_with("P-1", "T-1")
        self.assertIn("Trade Correlation Report", result.stdout)
        self.assertIn("Result: Not Correlated", result.stdout)
        self.assertIn("Amount mismatch", result.stdout)

    # --- [MLINT 2.0] Updated Graph & Stream CLI Tests ---

    @patch("chimera_intel.core.mlint.API_KEYS")
    @patch("chimera_intel.core.mlint.detect_graph_anomalies") # Patch the new real function
    @patch("chimera_intel.core.mlint.get_neo4j_driver")
    def test_cli_graph_run_gnn_anomaly(self, mock_get_driver, mock_detect_anomalies, mock_api_keys):
        """[MLINT 2.0] Tests the 'run-gnn-anomaly' command, which is no longer a placeholder."""
        # Arrange
        mock_api_keys.neo4j_uri = "bolt://localhost:7687"
        mock_api_keys.neo4j_user = "neo4j"
        mock_api_keys.neo4j_password = "password"
        
        mock_get_driver.return_value = MagicMock()
        mock_detect_anomalies.return_value = [
            GnnAnomalyResult(entity_id="A-123", anomaly_score=0.98, reason=["High PageRank"])
        ]

        # Act
        result = runner.invoke(mlint_app, ["graph", "run-gnn-anomaly"])
        
        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Running graph feature-based anomaly detection", result.stdout)
        self.assertIn("Graph Anomaly Report (Found 1)", result.stdout)
        self.assertIn("A-123", result.stdout)
        self.assertIn("High PageRank", result.stdout)
        self.assertNotIn("This is a placeholder", result.stdout)

    @patch("chimera_intel.core.mlint.API_KEYS")
    @patch("chimera_intel.core.mlint.KafkaProducer") # Mock the new Producer
    @patch("chimera_intel.core.mlint.KafkaConsumer")
    @patch("chimera_intel.core.mlint.get_neo4j_driver")
    @patch("chimera_intel.core.mlint.insert_transaction_to_neo4j")
    def test_cli_stream_start_consumer(
        self, mock_insert_neo4j, mock_get_driver, mock_kafka_consumer, 
        mock_kafka_producer, mock_api_keys
    ):
        """[MLINT 2.0] Tests the new 'stream start-consumer' pipeline."""
        # Arrange
        mock_api_keys.kafka_bootstrap_servers = "kafka:9092"
        mock_api_keys.kafka_topic_transactions = "txns"
        mock_api_keys.kafka_topic_scoring_jobs = "scoring_jobs" # New topic
        mock_api_keys.kafka_consumer_group = "mlint-test"
        mock_api_keys.neo4j_uri = "bolt://localhost:7687"
        mock_api_keys.neo4j_user = "neo4j"
        mock_api_keys.neo4j_password = "password"

        mock_get_driver.return_value = MagicMock()
        
        # Mock the KafkaConsumer to return one message and then stop
        mock_message = MagicMock()
        mock_message.value = {
            "id": "tx-123", "sender_id": "A", "receiver_id": "B", 
            "amount": 9500, "currency": "USD", "sender_jurisdiction": "USA", 
            "receiver_jurisdiction": "PA", "date": "2023-01-01T12:00:00"
        }
        
        mock_consumer_instance = MagicMock()
        mock_consumer_instance.__iter__.return_value = iter([mock_message, KeyboardInterrupt()])
        mock_kafka_consumer.return_value = mock_consumer_instance
        
        mock_producer_instance = MagicMock()
        mock_kafka_producer.return_value = mock_producer_instance

        # Act
        result = runner.invoke(mlint_app, ["stream", "start-consumer"])
        
        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        
        # 1. Check it subscribed to the right topic
        mock_kafka_consumer.assert_called_with(
            "txns", # topic_in
            bootstrap_servers=["kafka:9092"],
            auto_offset_reset='earliest',
            group_id='mlint-test',
            value_deserializer=unittest.mock.ANY
        )
        # 2. Check it processed the message
        self.assertIn("Received Transaction tx-123", result.stdout)
        self.assertIn("Sync Alerts:", result.stdout)
        self.assertIn("Potential Structuring", result.stdout)
        
        # 3. Check it inserted to Neo4j
        mock_insert_neo4j.assert_called_once()
        self.assertEqual(mock_insert_neo4j.call_args[0][1].id, "tx-123") # Check tx object
        
        # 4. Check it produced a job to the new topic
        self.assertIn("Published job tx-123 to 'scoring_jobs'", result.stdout)
        mock_producer_instance.send.assert_called_with(
            "scoring_jobs", # topic_out
            value={"tx_id": "tx-123", "sender_id": "A", "receiver_id": "B"}
        )

if __name__ == "__main__":
    unittest.main()