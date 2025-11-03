# Tests/test_covert_financial_tracking.py
import unittest
import logging
from unittest.mock import MagicMock, patch

# This patching assumes all modules are importable from this test context
patches = {
    'finint': patch('chimera_intel.core.covert_financial_tracking.FinancialIntelAnalyzer'),
    'blockchain': patch('chimera_intel.core.covert_financial_tracking.BlockchainOSINT'),
    'crypto': patch('chimera_intel.core.covert_financial_tracking.CryptoIntel'),
    'logistics': patch('chimera_intel.core.covert_financial_tracking.LogisticsIntel'),
    'supply_chain': patch('chimera_intel.core.covert_financial_tracking.SupplyChainRiskAnalyzer'),
    'dark_web': patch('chimera_intel.core.covert_financial_tracking.DarkWebMonitor'),
    'graph_db': patch('chimera_intel.core.covert_financial_tracking.GraphDB')
}

# Apply all patches
@patches['finint']
@patches['blockchain']
@patches['crypto']
@patches['logistics']
@patches['supply_chain']
@patches['dark_web']
@patches['graph_db']
class TestCovertFinancialTracker(unittest.TestCase):

    def setUp(self, MockGraphDB, MockDarkWeb, MockSupplyChain, MockLogistics, MockCrypto, MockBlockchain, MockFinINT):
        """Set up the test environment with mocked dependencies."""
        
        logging.disable(logging.CRITICAL) # Disable logging for tests
        
        # Instantiate mocks
        self.mock_graph_db = MockGraphDB()
        self.mock_finint = MockFinINT()
        self.mock_blockchain = MockBlockchain()
        self.mock_crypto = MockCrypto()
        self.mock_logistics = MockLogistics()
        self.mock_supply_chain = MockSupplyChain()
        self.mock_dark_web = MockDarkWeb()

        # --- Configure Mock Return Values ---

        # FinINT (Money Laundering)
        self.mock_finint.identify_shell_companies.return_value = [{"name": "Shell Co 1", "jurisdiction": "Panama"}]
        self.mock_finint.trace_offshore_accounts.return_value = [{"account": "12345", "bank": "Swiss Bank"}]
        self.mock_finint.extract_crypto_addresses.return_value = ["bc1q...", "0xAbC..."]
        
        # Blockchain
        self.mock_blockchain.check_mixer_activity.return_value = {"risk": "high", "source": "Tornado Cash"}

        # Logistics/SupplyChain
        self.mock_logistics.track_actor_shipments.return_value = [{"id": "SHIP-001", "origin": "Port A", "dest": "Port B"}]
        self.mock_supply_chain.analyze_shipment_risk.return_value = [{"id": "SHIP-001", "risk": "high"}]
        
        # FinINT (Trade Payments)
        self.mock_finint.find_payment_for_shipment.return_value = {"id": "PAY-001", "amount": 50000}
        self.mock_finint.is_payment_suspicious.return_value = True

        # DarkWeb
        self.mock_dark_web.scan_markets_for_keywords.return_value = [
            {"id": "LIST-1", "title": "AK-47s", "tags": ["weapon"], "vendor": "GunRunner"},
            {"id": "LIST-2", "title": "Windows 0day", "tags": ["exploit", "software"], "vendor": "Hackr"},
            {"id": "LIST-3", "title": "T-shirts", "tags": ["clothing"], "vendor": "Benign"},
        ]

        # --- Create the Class Under Test ---
        
        # Import here, after patches are active
        from chimera_intel.core.covert_financial_tracking import CovertFinancialTracker
        
        self.tracker = CovertFinancialTracker(graph_db=self.mock_graph_db)
        
        # Manually inject the other mocks (as they are initialized in the constructor in the main code)
        self.tracker.finint = self.mock_finint
        self.tracker.blockchain = self.mock_blockchain
        self.tracker.crypto = self.mock_crypto
        self.tracker.logistics = self.mock_logistics
        self.tracker.supply_chain = self.mock_supply_chain
        self.tracker.dark_web = self.mock_dark_web

    def tearDown(self):
        logging.disable(logging.NOTSET) # Re-enable logging

    def test_track_money_laundering(self):
        """Test the money laundering tracking module."""
        targets = ["Suspect A"]
        results = self.tracker.track_money_laundering(targets)

        self.mock_finint.identify_shell_companies.assert_called_with("Suspect A")
        self.mock_finint.trace_offshore_accounts.assert_called_with("Suspect A")
        self.assertEqual(len(results["shell_companies"]), 1)
        self.assertEqual(results["shell_companies"][0]["name"], "Shell Co 1")

        self.mock_finint.extract_crypto_addresses.assert_called_with("Suspect A")
        self.mock_blockchain.check_mixer_activity.assert_called_with("bc1q...")
        self.assertIn("bc1q...", results["crypto_mixers"])
        self.assertEqual(results["crypto_mixers"]["bc1q..."]["risk"], "high")

        self.mock_graph_db.add_edge.assert_called_with("Suspect A", "bc1q...", "HAS_CRYPTO_ADDRESS")

    def test_track_trade_espionage(self):
        """Test the trade and supply-chain espionage module."""
        actors = ["Suspect B"]
        results = self.tracker.track_trade_espionage(actors)

        self.mock_logistics.track_actor_shipments.assert_called_with("Suspect B")
        self.mock_supply_chain.analyze_shipment_risk.assert_called_with([{"id": "SHIP-001", "origin": "Port A", "dest": "Port B"}])
        self.assertEqual(len(results["suspicious_shipments"]), 1)
        
        self.mock_finint.find_payment_for_shipment.assert_called_with("SHIP-001")
        self.mock_finint.is_payment_suspicious.assert_called_with({"id": "PAY-001", "amount": 50000})
        self.assertEqual(len(results["linked_payments"]), 1)

        self.mock_graph_db.add_edge.assert_called_with("Suspect B", "SHIP-001", "ASSOCIATED_WITH")
        self.mock_graph_db.add_edge.assert_called_with("SHIP-001", "PAY-001", "PAID_BY")

    def test_scan_black_markets(self):
        """Test the black market / dark web scanning module."""
        keywords = ["weapon", "exploit"]
        results = self.tracker.scan_black_markets(keywords)

        self.mock_dark_web.scan_markets_for_keywords.assert_called_with(keywords)
        
        self.assertEqual(len(results["listings"]), 2) # LIST-3 should be filtered out
        self.assertEqual(results["listings"][0]["id"], "LIST-1")
        self.assertEqual(results["listings"][1]["id"], "LIST-2")

        self.mock_graph_db.add_edge.assert_called_with("Hackr", "LIST-2", "SELLING")

    def test_run_full_analysis(self):
        """Test the comprehensive analysis runner."""
        targets = ["Suspect C"]
        keywords = ["sensitive equipment"]
        
        # Mock the individual methods on the instance
        self.tracker.track_money_laundering = MagicMock(return_value="ml_report")
        self.tracker.track_trade_espionage = MagicMock(return_value="trade_report")
        self.tracker.scan_black_markets = MagicMock(return_value="market_report")
        
        report = self.tracker.run_full_analysis(targets, keywords)

        self.tracker.track_money_laundering.assert_called_with(targets)
        self.tracker.track_trade_espionage.assert_called_with(targets)
        self.tracker.scan_black_markets.assert_called_with(keywords)
        
        self.assertEqual(report["money_laundering"], "ml_report")
        self.assertEqual(report["trade_espionage"], "trade_report")
        self.assertEqual(report["black_market_scanning"], "market_report")

if __name__ == '__main__':
    unittest.main()