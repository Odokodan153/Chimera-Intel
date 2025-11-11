# tests/test_financial_market_signals.py

import unittest
from datetime import datetime, timedelta
from src.signals.financial_market_signals import (
    FinancialMarketSignalAnalyzer, FinancialDocument, ShippingRecord,
    Invoice, FundingEvent, Transaction
)

class TestFinancialMarketSignalAnalyzer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Initialize the analyzer once for all tests
        # This loads the spaCy model, which can be slow
        cls.analyzer = FinancialMarketSignalAnalyzer()

    def setUp(self):
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
        doc = FinancialDocument(
            doc_id="doc_123",
            source="Earnings Call Transcript",
            date=self.test_date,
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
        self.assertIn("Expansion", signal.key_topics)
        self.assertIn("Acme Corp, Inc.", signal.entities["ORG"])
        self.assertIn("Jane Doe", signal.entities["PERSON"])

    def test_match_trade_to_financials_fuzzy(self):
        """Test fuzzy matching for trade and logistics."""
        shipping = [
            # Case 1: Good match
            ShippingRecord("ship_001", "Globex Corporation", "1000 microchips", 1000, 50000.0, "Shanghai", "Rotterdam", self.test_date),
            # Case 2: Value mismatch
            ShippingRecord("ship_002", "Initech LLC", "50 printers", 50, 15000.0, "Taipei", "Long Beach", self.test_date),
            # Case 3: No date match
            ShippingRecord("ship_003", "Ollivanders", "wands", 10, 70.0, "London", "New York", self.test_date + timedelta(days=1)),
            # Case 4: Item mismatch
            ShippingRecord("ship_004", "Stark Industries", "parts", 200, 25000.0, "LA", "New York", self.test_date),
        ]
        invoices = [
            # Case 1: Matches ship_001
            Invoice("inv_A", "Supplier", "Globex Corp.", "microchips (1000 units)", 50000.0, self.test_date),
            # Case 2: Matches ship_002
            Invoice("inv_B", "Supplier", "Initech", "50 laserjet printers", 14500.0, self.test_date), 
            # Case 4: Matches ship_004
            Invoice("inv_C", "Supplier", "Stark Industries Inc.", "iron suits", 25000.0, self.test_date),
            # No match
            Invoice("inv_D", "Supplier", "Cyberdyne", "T-800", 1000000.0, self.test_date)
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
                self.assertEqual(m.value_discrepancy, 500.0)
            elif m.shipping_id == "ship_004":
                self.assertEqual(m.match_type, "Partial Match") # Value matches, item doesn't
                self.assertEqual(m.invoice_id, "inv_C")

    def test_detect_unusual_funding_activity_statistical(self):
        """Test statistical anomaly detection in funding data."""
        # Normal-looking data
        base_data = [
            FundingEvent(f"fe_{i}", "P", "proj_X", f"b_{i}", "N", 100.0 + (i*10), self.test_date)
            for i in range(10) # 100, 110, ..., 190
        ]
        # Anomaly
        anomaly_event = FundingEvent("fe_11", "P", "proj_X", "b_11", "Anomaly", 2000.0, self.test_date)
        
        funding_events = base_data + [anomaly_event]
        # Mean is approx 240, std dev is approx 540. Z-score for 2000 is ~3.2
        
        anomalies = self.analyzer.detect_unusual_funding_activity(funding_events, z_score_threshold=3.0)

        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].anomaly_type, "High Value Investment (Statistically)")
        self.assertEqual(anomalies[0].backer_id, "b_11")

    def test_correlate_payment_flows_networkx(self):
        """Test graph-based correlation of payments."""
        transactions = [
            Transaction("t1", "acc_corp_A", "acc_shell_B", 10000.0, self.test_date, "USD"),
            Transaction("t2", "acc_shell_B", "wallet_crypto_C", 9950.0, self.test_date + timedelta(days=1), "USD"),
            Transaction("t3", "acc_corp_A", "acc_corp_D", 5000.0, self.test_date, "USD"), # Normal flow
            Transaction("t4", "acc_shell_B", "acc_shell_E", 50.0, self.test_date + timedelta(days=1), "USD"),
            Transaction("t5", "acc_corp_A", "acc_shell_E", 100.0, self.test_date, "USD"), # Another path
            Transaction("t6", "acc_shell_E", "wallet_crypto_C", 100.0, self.test_date + timedelta(days=1), "USD"),
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

if __name__ == "__main__":
    unittest.main()