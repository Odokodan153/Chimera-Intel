import unittest
from chimera_intel.core.corporate_intel import (
    get_hiring_trends,
    get_employee_sentiment,
    get_trade_data,
    get_trademarks,
    get_lobbying_data,
)


class TestCorporateIntel(unittest.TestCase):
    """Test cases for the corporate_intel module."""

    def test_get_hiring_trends(self):
        """Tests the hiring trends analysis function."""
        result = get_hiring_trends("example.com")
        self.assertIsNotNone(result)
        self.assertGreater(result.total_postings, 0)
        self.assertIn("R&D", result.trends_by_department)

    def test_get_employee_sentiment(self):
        """Tests the employee sentiment analysis function."""
        result = get_employee_sentiment("Example Corp")
        self.assertIsNotNone(result)
        self.assertGreater(result.overall_rating, 0)

    def test_get_trade_data(self):
        """Tests the trade data retrieval function."""
        result = get_trade_data("Example Corp")
        self.assertIsNotNone(result)
        self.assertEqual(result.total_shipments, 1)
        self.assertIn("Microchip", result.shipments[0].product_description)

    def test_get_trademarks(self):
        """Tests the trademark search function."""
        result = get_trademarks("Example Corp")
        self.assertIsNotNone(result)
        self.assertEqual(result.total_found, 1)
        self.assertIn("Project Chimera", result.trademarks[0].description)

    def test_get_lobbying_data(self):
        """Tests the lobbying data analysis function."""
        result = get_lobbying_data("Example Corp")
        self.assertIsNotNone(result)
        self.assertGreater(result.total_spent, 0)
        self.assertEqual(result.records[0].year, 2025)


if __name__ == "__main__":
    unittest.main()
