import unittest
from src.chimera_intel.core.qint import QInt


class TestQInt(unittest.TestCase):
    def setUp(self):
        self.qint = QInt()

    def test_scrape_quantum_research_live(self):
        """Tests live data scraping from arXiv."""
        papers = self.qint.scrape_quantum_research("quantum", max_results=1)
        self.assertIsInstance(papers, list)
        if papers:
            self.assertIn("title", papers[0])
            self.assertIn("authors", papers[0])

    def test_analyze_trl_structure(self):
        """Tests the structure of the TRL analysis, which is based on curated data."""
        result = self.qint.analyze_trl("IBM")
        self.assertIn("estimated_trl", result)
        self.assertIn("assessment", result)
        self.assertEqual(result["entity"], "IBM")

    def test_monitor_pqc_live(self):
        """Tests live scraping of the NIST PQC page."""
        algorithms = self.qint.monitor_pqc()
        self.assertIsInstance(algorithms, list)
        if algorithms:
            self.assertIn("algorithm", algorithms[0])
            self.assertIn("status", algorithms[0])


if __name__ == "__main__":
    unittest.main()
