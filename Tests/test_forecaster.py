import unittest
from unittest.mock import patch
from chimera_intel.core.forecaster import get_all_scans_for_target, run_prediction_rules


class TestForecaster(unittest.TestCase):
    """Test cases for the forecaster module."""

    @patch("chimera_intel.core.forecaster.sqlite3.connect")
    def test_get_all_scans_for_target_success(self, mock_connect):
        """Tests retrieving all historical scans for a target."""
        mock_cursor = mock_connect.return_value.cursor.return_value
        mock_cursor.fetchall.return_value = [
            ('{"news": {"totalArticles": 10}}',),
            ('{"news": {"totalArticles": 5}}',),
        ]

        scans = get_all_scans_for_target("example.com", "business_intel")
        self.assertEqual(len(scans), 2)
        self.assertEqual(scans[0]["news"]["totalArticles"], 10)

    @patch("chimera_intel.core.forecaster.sqlite3.connect")
    def test_get_all_scans_for_target_db_error(self, mock_connect):
        """Tests scan retrieval when a database error occurs."""
        mock_connect.side_effect = Exception("DB connection failed")
        scans = get_all_scans_for_target("example.com", "business_intel")
        self.assertEqual(scans, [])

    def test_run_prediction_rules_not_enough_data(self):
        """Tests prediction rules when there is not enough historical data."""
        result = run_prediction_rules([{}], "business_intel")
        self.assertIn("Not enough historical data", result.notes)

    def test_run_prediction_rules_high_news_volume(self):
        """Tests the 'High News Volume' prediction rule."""
        historical_data = [
            {"business_intel": {"news": {"totalArticles": 5}}},
            {"business_intel": {"news": {"totalArticles": 15}}},
        ]
        result = run_prediction_rules(historical_data, "business_intel")
        self.assertEqual(len(result.predictions), 1)
        self.assertIn("High News Volume", result.predictions[0].signal)

    def test_run_prediction_rules_new_patents(self):
        """Tests the 'Innovation Signal' prediction rule for new patents."""
        historical_data = [
            {"business_intel": {"patents": {"patents": [{"title": "Old Patent"}]}}},
            {
                "business_intel": {
                    "patents": {
                        "patents": [{"title": "Old Patent"}, {"title": "New Patent"}]
                    }
                }
            },
        ]
        result = run_prediction_rules(historical_data, "business_intel")
        self.assertEqual(len(result.predictions), 1)
        self.assertIn("Innovation Signal", result.predictions[0].signal)

    def test_run_prediction_rules_new_marketing_tech(self):
        """Tests the 'Marketing Expansion Signal' prediction rule."""
        historical_data = [
            {"web_analysis": {"tech_stack": {"results": [{"technology": "React"}]}}},
            {
                "web_analysis": {
                    "tech_stack": {
                        "results": [{"technology": "React"}, {"technology": "HubSpot"}]
                    }
                }
            },
        ]
        result = run_prediction_rules(historical_data, "web_analyzer")
        self.assertEqual(len(result.predictions), 1)
        self.assertIn("Marketing Expansion Signal", result.predictions[0].signal)

    def test_run_prediction_rules_no_signals(self):
        """Tests prediction rules when no strong signals are detected."""
        historical_data = [
            {"business_intel": {"news": {"totalArticles": 5}}},
            {"business_intel": {"news": {"totalArticles": 6}}},
        ]
        result = run_prediction_rules(historical_data, "business_intel")
        self.assertEqual(len(result.predictions), 0)
        self.assertIn("No strong predictive signals", result.notes)


if __name__ == "__main__":
    unittest.main()
