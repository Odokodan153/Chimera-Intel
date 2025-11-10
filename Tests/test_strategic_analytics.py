import unittest
import json
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from datetime import datetime, timedelta

# Import the 'app' from the new module
from chimera_intel.core.strategic_analytics import app

runner = CliRunner()

# --- Mock Data ---

MOCK_NOW = datetime(2025, 11, 10, 12, 0, 0)

MOCK_PRICE_HISTORY = [
    {
        "url": "https://example.com/product/123",
        "timestamp": (MOCK_NOW - timedelta(hours=2)).isoformat(),
        "sale_price": 99.99,
    },
    {
        "url": "https://example.com/product/123",
        "timestamp": (MOCK_NOW - timedelta(hours=10)).isoformat(),
        "sale_price": 109.99,
    },
    {
        "url": "https://example.com/product/456",
        "timestamp": (MOCK_NOW - timedelta(hours=6)).isoformat(),
        "sale_price": 50.00,
    },
    {
        "url": "https://another-competitor.com/product/789",
        "timestamp": (MOCK_NOW - timedelta(hours=1)).isoformat(),
        "sale_price": 19.99,
    },
]

MOCK_AGG_DATA = {
    "target": "example.com",
    "modules": {
        "dns_scan": {"status": "completed"},
        "port_scan": {"status": "completed"},
        "web_analysis": {"status": "completed"},
    },
}


class TestStrategicAnalytics(unittest.TestCase):
    @patch("chimera_intel.core.strategic_analytics.datetime")
    @patch("chimera_intel.core.strategic_analytics.get_aggregated_data_for_target")
    @patch("chimera_intel.core.strategic_analytics._load_price_history")
    def test_kpi_report_success(
        self, mock_load_history, mock_get_agg_data, mock_datetime
    ):
        """Tests a successful KPI report generation."""
        # Arrange
        mock_load_history.return_value = MOCK_PRICE_HISTORY
        mock_get_agg_data.return_value = MOCK_AGG_DATA
        mock_datetime.now.return_value = MOCK_NOW

        # Act
        result = runner.invoke(app, ["kpi-report", "example.com"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        mock_load_history.assert_called_once()
        mock_get_agg_data.assert_called_with("example.com")
        
        # 1. Coverage
        self.assertIn("Tracked SKUs (from PRICEINT): 2", result.stdout)
        self.assertIn("Tracked Data Modules (from DB): 3", result.stdout)
        
        # 2. Freshness (median of 2 hours and 6 hours)
        # (2h + 6h) / 2 = 4h
        # median(2, 6) = 4h
        self.assertIn("Median Data Freshness (Pricing): 4.00 hours", result.stdout)
        self.assertIn("Average Data Freshness (Pricing): 4.00 hours", result.stdout)
        
        # 3. Qualitative KPIs
        self.assertIn("Signal Precision", result.stdout)
        self.assertIn("Time-to-Insight", result.stdout)
        
        # 4. Governance Notes
        self.assertIn("respect robots.txt", result.stdout)
        self.assertIn("per GDPR/privacy policies", result.stdout)

    @patch("chimera_intel.core.strategic_analytics.datetime")
    @patch("chimera_intel.core.strategic_analytics.get_aggregated_data_for_target")
    @patch("chimera_intel.core.strategic_analytics._load_price_history")
    def test_kpi_report_no_data(
        self, mock_load_history, mock_get_agg_data, mock_datetime
    ):
        """Tests the report when no data is found for the target."""
        # Arrange
        mock_load_history.return_value = MOCK_PRICE_HISTORY  # Return all data
        mock_get_agg_data.return_value = None  # No DB data
        mock_datetime.now.return_value = MOCK_NOW

        # Act
        # Ask for a domain that is not in the mock history
        result = runner.invoke(app, ["kpi-report", "nonexistent.com"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        
        # 1. Coverage
        self.assertIn("Tracked SKUs (from PRICEINT): 0", result.stdout)
        self.assertIn("No aggregated scan data found", result.stdout)
        
        # 2. Freshness
        self.assertIn("No pricing data found to calculate freshness", result.stdout)


if __name__ == "__main__":
    unittest.main()