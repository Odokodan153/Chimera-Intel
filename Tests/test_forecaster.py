import unittest
from unittest.mock import patch
from typer.testing import CliRunner
import typer

from chimera_intel.cli import app
from chimera_intel.core.forecaster import get_all_scans_for_target, run_prediction_rules
from chimera_intel.core.schemas import ProjectConfig

runner = CliRunner()


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

    # --- CLI Tests ---

    @patch("chimera_intel.core.forecaster.resolve_target")
    @patch("chimera_intel.core.forecaster.get_all_scans_for_target")
    def test_cli_forecast_with_project(self, mock_get_scans, mock_resolve_target):
        """Tests the CLI command using the centralized target resolver."""
        # Arrange

        mock_resolve_target.return_value = "project.com"
        mock_get_scans.return_value = []  # Not enough data, but we check the logic

        # Act

        result = runner.invoke(app, ["analysis", "forecast", "run", "footprint"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_resolve_target.assert_called_once_with(None, required_assets=["domain"])
        mock_get_scans.assert_called_with("project.com", "footprint")

    @patch("chimera_intel.core.forecaster.resolve_target")
    def test_cli_forecast_resolver_fails(self, mock_resolve_target):
        """Tests the CLI command when the resolver raises an exit exception."""
        # Arrange

        mock_resolve_target.side_effect = typer.Exit(code=1)

        # Act

        result = runner.invoke(app, ["analysis", "forecast", "run", "footprint"])

        # Assert

        self.assertEqual(result.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
