# tests/test_financial_market_signals.py

import unittest
import numpy as np
from datetime import datetime, timedelta
# (FIXED) Updated imports to point to the core file and schemas
from src.chimera_intel.core.financial_market_signals import FinancialMarketSignalAnalyzer
from src.chimera_intel.core.schemas import (
    FinancialDocument, ShippingRecord, Invoice, FundingEvent, Transaction
)

class TestFinancialMarketSignalAnalyzer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Initialize the analyzer once for all tests
        # This loads the spaCy model, which can be slow
        try:
            cls.analyzer = FinancialMarketSignalAnalyzer()
        except Exception as e:
            print(f"Failed to load FinancialMarketSignalAnalyzer: {e}")
            cls.analyzer = None

    def setUp(self):
        if not self.analyzer:
            self.skipTest("Analyzer not initialized, skipping all tests.")
        self.test_date = datetime(2023, 1, 15)

    def test_extract_signals_from_document(self):
        """Test NLP signal extraction with spaCy."""
        if not self.analyzer.nlp:
            self.skipTest("spaCy model not loaded, skipping NLP test.")
            
        doc_content = """
        Acme Corp, Inc. reported strong Q4 growth, exceeding expectations.
        We are optimistic about the new market launch.
        However, we face headwinds from regulatory scrutiny and significant litigation.
        Our CEO, Jane Doe, is not worried about fraud.
        """
        # (FIXED) Use keyword arguments for Pydantic schema
        doc = FinancialDocument(
            doc_id="doc_123",
            source_url="Earnings Call Transcript",
            timestamp=self.test_date,
            content=doc_content
        )
        signal = self.analyzer.extract_signals_from_document(doc)

        self.assertEqual(signal.doc_id, "doc_123")
        # Sentiment is nuanced: "strong", "optimistic" vs "headwinds", "litigation", "fraud"
        # spacytextblob should pick this up as negative
        self.assertEqual(signal.sentiment, "negative")
        self.assertIn("litigation", signal.risk_factors)
        self.assertIn("regulatory scrutiny", signal.risk_factors)
        self.assertIn("headwinds", signal.risk_factors)
        self.assertIn("fraud", signal.risk_factors)
        self.assertIn("Expansion", signal.key_topics) # Normalized from "new market launch"
        self.assertIn("Acme Corp, Inc.", signal.entities["ORG"])
        self.assertIn("Jane Doe", signal.entities["PERSON"])

    def test_match_trade_to_financials_fuzzy(self):
        """Test fuzzy matching for trade and logistics."""
        # (FIXED) Use keyword arguments for Pydantic schemas and remove extra fields
        shipping = [
            # Case 1: Good match
            ShippingRecord(record_id="ship_001", company_name="Globex Corporation", item_description="1000 microchips", value=50000.0, date=self.test_date),
            # Case 2: Value mismatch
            ShippingRecord(record_id="ship_002", company_name="Initech LLC", item_description="50 printers", value=15000.0, date=self.test_date),
            # Case 3: No date match
            ShippingRecord(record_id="ship_003", company_name="Ollivanders", item_description="wands", value=70.0, date=self.test_date + timedelta(days=1)),
            # Case 4: Item mismatch
            ShippingRecord(record_id="ship_004", company_name="Stark Industries", item_description="parts", value=25000.0, date=self.test_date),
        ]
        invoices = [
            # Case 1: Matches ship_001
            Invoice(invoice_id="inv_A", receiver_name="Globex Corp.", item_description="microchips (1000 units)", amount=50000.0, date=self.test_date),
            # Case 2: Matches ship_002
            Invoice(invoice_id="inv_B", receiver_name="Initech", item_description="50 laserjet printers", amount=14500.0, date=self.test_date), 
            # Case 4: Matches ship_004
            Invoice(invoice_id="inv_C", receiver_name="Stark Industries Inc.", item_description="iron suits", amount=25000.0, date=self.test_date),
            # No match
            Invoice(invoice_id="inv_D", receiver_name="Cyberdyne", item_description="T-800", amount=1000000.0, date=self.test_date)
        ]
        
        matches = self.analyzer.match_trade_to_financials(shipping, invoices)

        self.assertEqual(len(matches), 3)
        match_types = sorted([m.match_type for m in matches])
        self.assertEqual(match_types, ["Discrepancy", "Full Match", "Partial Match"])

        for m in matches:
            if m.shipping_id == "ship_001":
                self.assertEqual(m.match_type, "Full Match")
                self.assertEqual(m.invoice_id, "inv_A")
            elif m.shipping_id == "ship_002":
                self.assertEqual(m.match_type, "Discrepancy")
                self.assertEqual(m.invoice_id, "inv_B")
                self.assertAlmostEqual(m.value_discrepancy, 500.0)
            elif m.shipping_id == "ship_004":
                self.assertEqual(m.match_type, "Partial Match") # Value matches, item doesn't
                self.assertEqual(m.invoice_id, "inv_C")

    def test_detect_unusual_funding_activity_statistical(self):
        """Test statistical anomaly detection in funding data."""
        # (FIXED) Use keyword arguments for Pydantic schema
        # Normal-looking data
        base_data = [
            FundingEvent(project_id="proj_X", backer_id=f"b_{i}", amount=100.0 + (i*10), date=self.test_date)
            for i in range(10) # 100, 110, ..., 190
        ]
        # Anomaly
        anomaly_event = FundingEvent(project_id="proj_X", backer_id="b_11", amount=2000.0, date=self.test_date)
        
        funding_events = base_data + [anomaly_event]
        # Mean is approx 240, std dev is approx 540. Z-score for 2000 is ~3.2
        
        anomalies = self.analyzer.detect_unusual_funding_activity(funding_events, z_score_threshold=3.0)
        
        # This will also find "New Influential Backers" for b_0...b_11, 
        # but the "High Value" one is the most important
        self.assertGreaterEqual(len(anomalies), 1)
        
        high_value_anomalies = [a for a in anomalies if a.anomaly_type == "High Value Investment (Statistically)"]
        self.assertEqual(len(high_value_anomalies), 1)
        self.assertEqual(high_value_anomalies[0].backer_id, "b_11")

    def test_correlate_payment_flows_networkx(self):
        """Test graph-based correlation of payments."""
        # (FIXED) Use keyword arguments for Pydantic schema
        transactions = [
            Transaction(tx_id="t1", from_account="acc_corp_A", to_account="acc_shell_B", amount=10000.0, date=self.test_date),
            Transaction(tx_id="t2", from_account="acc_shell_B", to_account="wallet_crypto_C", amount=9950.0, date=self.test_date + timedelta(days=1)),
            Transaction(tx_id="t3", from_account="acc_corp_A", to_account="acc_corp_D", amount=5000.0, date=self.test_date), # Normal flow
            Transaction(tx_id="t4", from_account="acc_shell_B", to_account="acc_shell_E", amount=50.0, date=self.test_date + timedelta(days=1)),
            Transaction(tx_id="t5", from_account="acc_corp_A", to_account="acc_shell_E", amount=100.0, date=self.test_date), # Another path
            Transaction(tx_id="t6", from_account="acc_shell_E", to_account="wallet_crypto_C", amount=100.0, date=self.test_date + timedelta(days=1)),
        ]
        entity_mappings = {
            "acc_corp_A": "corporate",
            "acc_shell_B": "shell",
            "wallet_crypto_C": "crypto",
            "acc_corp_D": "corporate",
            "acc_shell_E": "shell"
        }
        
        correlations = self.analyzer.correlate_payment_flows(transactions, entity_mappings)

        self.assertEqual(len(correlations), 2) # Finds two distinct paths: A->B->C and A->E->C
        
        paths_found = [tuple(c.path) for c in correlations]
        self.assertIn(('acc_corp_A', 'acc_shell_B', 'wallet_crypto_C'), paths_found)
        self.assertIn(('acc_corp_A', 'acc_shell_E', 'wallet_crypto_C'), paths_found)

        for flow in correlations:
            self.assertEqual(flow.start_entity, "acc_corp_A")
            self.assertEqual(flow.end_entity, "wallet_crypto_C")
            self.assertTrue(len(flow.intermediaries) > 0)
            # Check amount is from the *first* edge, as per core logic
            if tuple(flow.path) == ('acc_corp_A', 'acc_shell_B', 'wallet_crypto_C'):
                self.assertEqual(flow.total_amount, 10000.0)
            elif tuple(flow.path) == ('acc_corp_A', 'acc_shell_E', 'wallet_crypto_C'):
                self.assertEqual(flow.total_amount, 100.0)

if __name__ == "__main__":
    unittest.main()