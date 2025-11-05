import unittest
import json
import tempfile
import os
import anyio
import httpx
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner
from datetime import date, timedelta
import pandas as pd

# Import the app and all functions/schemas to be tested
# Imports are all updated to the new structure
from chimera_intel.core.mlint import mlint_app
from chimera_intel.core.mlint_analysis import (
    analyze_transactions,
    analyze_entity_risk,
    get_jurisdiction_risk,
    get_ubo_data,
    check_crypto_wallet,
    export_entity_to_stix,
)
from chimera_intel.core.mlint_graph import (
    detect_graph_anomalies
)
from chimera_intel.core.mlint_linking import (
    resolve_entities,
    correlate_trade_payment
)
# Import schemas from the main core.schemas file
from chimera_intel.core.schemas import (
    EntityRiskResult,
    CryptoWalletScreenResult,
    Transaction,
    TransactionAnalysisResult,
    SwiftTransactionAnalysisResult,
    UboResult,
    UboData,
    GnnAnomalyResult,
    EntityLink,
    EntityResolutionResult,
    TradeData,
    PaymentData,
    TradeCorrelationResult
)

runner = CliRunner()


class TestMlint(unittest.TestCase):
    """
    Test cases for the refactored and implemented MLINT package.
    """

    # --- Core Function Tests (from mlint_analysis.py) ---

    def test_get_jurisdiction_risk_lists(self):
        high = get_jurisdiction_risk("North Korea"); self.assertEqual(high.risk_level, "High")
        med = get_jurisdiction_risk("Panama"); self.assertEqual(med.risk_level, "Medium")
        low = get_jurisdiction_risk("Canada"); self.assertEqual(low.risk_level, "Low")

    @patch("chimera_intel.core.mlint_analysis.get_neo4j_driver")
    @patch("chimera_intel.core.mlint_analysis.MLINT_AML_API_URL", "http://fake-api.com")
    @patch("chimera_intel.core.mlint_analysis.API_KEYS")
    @patch("chimera_intel.core.mlint_analysis.httpx.AsyncClient")
    def test_get_ubo_data_writes_to_graph(self, mock_async_client, mock_api_keys, mock_aml_url, mock_get_driver):
        """[MLINT 2.0] Tests that get_ubo_data calls graph update helpers."""
        # Arrange
        mock_api_keys.open_corporates_api_key = "fake_ubo_key"
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "ultimate_beneficial_owners": [
                {"name": "Owner One", "ownership_percentage": 75.0, "is_pep": True}
            ]
        }
        mock_async_client.return_value.__aenter__.return_value.get.return_value = mock_response
        
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver.session.return_value = mock_session
        mock_get_driver.return_value = mock_driver

        # Act
        result = anyio.run(get_ubo_data, "TestCo")

        # Assert
        self.assertIsNone(result.error)
        self.assertEqual(result.ultimate_beneficial_owners[0].name, "Owner One")
        
        # Check that the graph was called
        mock_get_driver.assert_called_once()
        mock_session.run.assert_called()
        self.assertIn("MERGE (c:Company {name: $company_name})", mock_session.run.call_args_list[0][0][0])
        self.assertIn("MERGE (c)-[r:HAS_UBO]->(p)", mock_session.run.call_args_list[1][0][0])

    # --- [MLINT 2.0] New Linking Function Tests (mlint_linking.py) ---

    @patch("chimera_intel.core.mlint_linking.get_neo4j_driver")
    @patch("chimera_intel.core.mlint_linking.analyze_entity_risk", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint_linking.check_crypto_wallet", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint_linking.get_ubo_data", new_callable=AsyncMock)
    def test_resolve_entities_full_implementation(self, mock_get_ubo, mock_check_wallet, mock_analyze_risk, mock_get_driver):
        """[MLINT 2.0] Tests the new entity resolution implementation."""
        # Arrange
        # 1. Mock API calls
        mock_get_ubo.return_value = UboResult(
            company_name="TestCo",
            ultimate_beneficial_owners=[UboData(name="John Doe", is_pep=True)]
        )
        mock_check_wallet.return_value = CryptoWalletScreenResult(
            wallet_address="123-wallet", mixer_interaction=True
        )
        mock_analyze_risk.return_value = EntityRiskResult(
            company_name="John Doe", sanctions_hits=1
        )
        
        # 2. Mock Neo4j
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_result = [
            {
                "s_type": "Company", "s_id": "TestCo",
                "r_type": "HAS_UBO",
                "e_type": "Person", "e_id": "John Doe"
            }
        ]
        mock_session.run.return_value = mock_result
        mock_driver.session.return_value = mock_session
        mock_get_driver.return_value = mock_driver

        # Act
        result = anyio.run(
            resolve_entities,
            company_names=["TestCo"],
            wallet_addresses=["123-wallet"],
            person_names=["John Doe"]
        )

        # Assert
        self.assertIsNone(result.error)
        
        # Check API-driven links
        link_descs = {l.description for l in result.links}
        self.assertIn("Wallet interacted with a known mixer.", link_descs)
        self.assertIn("Person is on 1 sanctions list(s).", link_descs)
        
        # Check Graph-driven links
        self.assertIn("Graph link: Company:TestCo -> HAS_UBO -> Person:John Doe", link_descs)
        
        # Check resolved entities
        self.assertIn("Company:TestCo", result.resolved_entities)
        self.assertIn("Person:John Doe", result.resolved_entities)
        self.assertIn("Wallet:123-wallet", result.resolved_entities)
        self.assertIn("Entity:Mixer", result.resolved_entities)
        self.assertIn("Entity:Sanctioned", result.resolved_entities)

    @patch("chimera_intel.core.mlint_linking.fuzz.token_set_ratio")
    @patch("chimera_intel.core.mlint_linking.fetch_payment_data", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint_linking.fetch_trade_data", new_callable=AsyncMock)
    @patch("chimera_intel.core.mlint_linking.API_KEYS")
    def test_correlate_trade_payment_full_implementation(self, mock_api_keys, mock_fetch_trade, mock_fetch_payment, mock_fuzz):
        """[MLINT 2.0] Tests the new trade correlation implementation."""
        # Arrange
        mock_api_keys.trade_api_key = "fake"
        mock_api_keys.aml_api_key = "fake"
        
        # 1. Mock API data
        mock_fetch_trade.return_value = TradeData(
            document_id="BOL-123", invoice_amount=10000.00,
            exporter_name="Global Exporters Inc", importer_name="Local Importers Ltd",
            ship_date=date(2023, 1, 1)
        )
        mock_fetch_payment.return_value = PaymentData(
            payment_id="SW-456", amount=9900.00, # Within tolerance
            sender_name="Global Exporters", # Fuzzy match
            receiver_name="Local Importers Ltd", # Exact match
            payment_date=date(2023, 1, 15) # Within date range
        )
        
        # 2. Mock fuzzy matching
        mock_fuzz.side_effect = [
            90, # Sender match (Global Exporters vs Global Exporters Inc)
            100 # Receiver match (Local Importers Ltd vs Local Importers Ltd)
        ]

        # Act
        result = anyio.run(correlate_trade_payment, "SW-456", "BOL-123")
        
        # Assert
        self.assertIsNone(result.error)
        self.assertTrue(result.is_correlated)
        self.assertEqual(result.confidence, "High")
        self.assertEqual(result.correlation_score, 1.0) # 0.4 (amt) + 0.1 (date) + 0.25 (sender) + 0.25 (receiver)
        self.assertEqual(len(result.mismatches), 0)

    # --- CLI Command Tests (from mlint.py) ---

    @patch("chimera_intel.core.mlint.analyze_entity_risk", new_callable=AsyncMock)
    def test_cli_check_entity(self, mock_analyze_entity):
        """Tests the 'check-entity' command."""
        mock_analyze_entity.return_value = EntityRiskResult(
            company_name="TestCo", jurisdiction="Panama",
            risk_score=70, risk_factors=["FATF Grey List"],
        )
        result = runner.invoke(mlint_app, ["check-entity", "--company-name", "TestCo", "--jurisdiction", "Panama"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Entity Risk Report for TestCo", result.stdout)

    @patch("chimera_intel.core.mlint.resolve_entities", new_callable=AsyncMock)
    def test_cli_resolve(self, mock_resolve):
        """[MLINT 2.0] Tests the 'mlint resolve' CLI command."""
        mock_resolve.return_value = EntityResolutionResult(
            total_entities_found=3,
            links=[EntityLink(source="Wallet:123", target="Entity:Mixer", type="INTERACTED_WITH", description="...")]
        )
        result = runner.invoke(mlint_app, ["resolve", "--wallet", "123"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Entity Resolution Report", result.stdout)
        self.assertIn("Wallet:123 --(INTERACTED_WITH)--> Entity:Mixer", result.stdout)

    @patch("chimera_intel.core.mlint.correlate_trade_payment", new_callable=AsyncMock)
    def test_cli_correlate_trade(self, mock_correlate):
        """[MLINT 2.0] Tests the 'mlint correlate-trade' CLI command."""
        mock_correlate.return_value = TradeCorrelationResult(
            is_correlated=True, confidence="High", correlation_score=0.9
        )
        result = runner.invoke(mlint_app, ["correlate-trade", "--payment-id", "P-1", "--trade-doc-id", "T-1"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Trade Correlation Report", result.stdout)
        self.assertIn("Result: Correlated", result.stdout)
        self.assertIn("Confidence: High", result.stdout)

    @patch("chimera_intel.core.mlint.detect_graph_anomalies")
    @patch("chimera_intel.core.mlint.get_neo4j_driver")
    def test_cli_graph_run_gnn_anomaly(self, mock_get_driver, mock_detect_anomalies):
        """[MLINT 2.0] Tests the 'run-gnn-anomaly' command."""
        mock_get_driver.return_value = MagicMock()
        mock_detect_anomalies.return_value = [
            GnnAnomalyResult(entity_id="A-123", anomaly_score=0.98, reason=["High PageRank"])
        ]
        result = runner.invoke(mlint_app, ["graph", "run-gnn-anomaly"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Graph Anomaly Report (Found 1)", result.stdout)

    @patch("chimera_intel.core.mlint.run_kafka_consumer")
    def test_cli_stream_start_consumer(self, mock_run_consumer):
        """[MLINT 2.0] Tests the 'stream start-consumer' CLI command."""
        result = runner.invoke(mlint_app, ["stream", "start-consumer"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        mock_run_consumer.assert_called_once()


if __name__ == "__main__":
    unittest.main()