import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
import typer
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from datetime import datetime, timedelta

from chimera_intel.cli import app
from chimera_intel.core.forecaster import (
    get_all_scans_for_target,
    run_prediction_rules,
    predict_breach_likelihood,
    predict_acquisition_likelihood,
    check_for_missed_events,
    train_breach_prediction_model,
)

runner = CliRunner()


class TestForecaster(unittest.TestCase):
    """Test cases for the forecaster module."""

    @patch("chimera_intel.core.forecaster.get_all_scans_for_target")
    def test_get_all_scans_for_target_success(self, mock_get_scans):
        """Tests retrieving all historical scans for a target."""
        # This function is now expected to return a list of dicts

        mock_get_scans.return_value = [
            {"scan_data": {"news": {"totalArticles": 10}}, "timestamp": datetime.now()}
        ]

        scans = get_all_scans_for_target("example.com", "business_intel")
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["scan_data"]["news"]["totalArticles"], 10)

    @patch("chimera_intel.core.forecaster.get_all_scans_for_target")
    def test_get_all_scans_for_target_db_error(self, mock_get_scans):
        """Tests scan retrieval when a database error occurs."""
        mock_get_scans.side_effect = Exception("DB connection failed")
        scans = get_all_scans_for_target("example.com", "business_intel")
        self.assertEqual(scans, [])

    def test_run_prediction_rules_not_enough_data(self):
        """Tests prediction rules when there is not enough historical data."""
        result = run_prediction_rules([{}], "business_intel")
        self.assertIn("Not enough historical data", result.notes)

    def test_run_prediction_rules_high_news_volume(self):
        """Tests the 'High News Volume' prediction rule."""
        historical_data = [
            {"scan_data": {"business_intel": {"news": {"totalArticles": 5}}}},
            {"scan_data": {"business_intel": {"news": {"totalArticles": 15}}}},
        ]
        result = run_prediction_rules(historical_data, "business_intel")
        self.assertEqual(len(result.predictions), 1)
        self.assertIn("High News Volume", result.predictions[0].signal)

    def test_run_prediction_rules_new_patents(self):
        """Tests the 'Innovation Signal' prediction rule for new patents."""
        historical_data = [
            {
                "scan_data": {
                    "business_intel": {
                        "patents": {"patents": [{"title": "Old Patent"}]}
                    }
                }
            },
            {
                "scan_data": {
                    "business_intel": {
                        "patents": {
                            "patents": [
                                {"title": "Old Patent"},
                                {"title": "New Patent"},
                            ]
                        }
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
            {
                "scan_data": {
                    "web_analysis": {
                        "tech_stack": {"results": [{"technology": "React"}]}
                    }
                }
            },
            {
                "scan_data": {
                    "web_analysis": {
                        "tech_stack": {
                            "results": [
                                {"technology": "React"},
                                {"technology": "HubSpot"},
                            ]
                        }
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
            {"scan_data": {"business_intel": {"news": {"totalArticles": 5}}}},
            {"scan_data": {"business_intel": {"news": {"totalArticles": 6}}}},
        ]
        result = run_prediction_rules(historical_data, "business_intel")
        self.assertEqual(len(result.predictions), 0)
        self.assertIn("No strong predictive signals", result.notes)

    def test_check_for_missed_events_is_missed(self):
        """Tests that a missed event is correctly identified."""
        # Arrange: Mock data where the last financial report was 100 days ago

        historical_data = [
            {
                "scan_data": {
                    "business_intel": {"financials": {"companyName": "TestCorp"}}
                },
                "timestamp": datetime.now() - timedelta(days=100),
            }
        ]

        # Act

        missed = check_for_missed_events(
            "example.com", historical_data, "business_intel"
        )

        # Assert

        self.assertEqual(len(missed), 1)
        self.assertIn("was not observed in the last 95 days", missed[0])

    def test_check_for_missed_events_not_missed(self):
        """Tests that a recent event is not flagged as missed."""
        # Arrange: Mock data where the last financial report was 30 days ago

        historical_data = [
            {
                "scan_data": {
                    "business_intel": {"financials": {"companyName": "TestCorp"}}
                },
                "timestamp": datetime.now() - timedelta(days=30),
            }
        ]

        # Act

        missed = check_for_missed_events(
            "example.com", historical_data, "business_intel"
        )

        # Assert

        self.assertEqual(len(missed), 0)

    def test_check_for_missed_events_no_prior_data(self):
        """Tests that no missed events are flagged if no prior occurrences exist."""
        # Arrange: Mock data that doesn't contain the expected event field

        historical_data = [
            {
                "scan_data": {"some_other_module": {"data": "value"}},
                "timestamp": datetime.now() - timedelta(days=100),
            }
        ]

        # Act

        missed = check_for_missed_events(
            "example.com", historical_data, "business_intel"
        )

        # Assert

        self.assertEqual(len(missed), 0)

    @patch("chimera_intel.core.forecaster.joblib.load")
    def test_predict_breach_likelihood_high_risk(self, mock_joblib_load):
        """Tests the breach prediction with a high-risk scenario."""
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.1, 0.9]])
        mock_joblib_load.return_value = mock_model

        scan_data = {
            "vulnerability_scanner": {
                "scanned_hosts": [{"open_ports": [{"vulnerabilities": [1, 2]}]}]
            }
        }
        prediction = predict_breach_likelihood(scan_data)

        self.assertIsNotNone(prediction)
        self.assertIn("High Likelihood of Data Breach", prediction.signal)

    @patch("chimera_intel.core.forecaster.joblib.load")
    def test_predict_breach_likelihood_low_risk(self, mock_joblib_load):
        """Tests the breach prediction with a low-risk scenario."""
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.8, 0.2]])
        mock_joblib_load.return_value = mock_model

        scan_data = {}
        prediction = predict_breach_likelihood(scan_data)

        self.assertIsNone(prediction)

    def test_predict_acquisition_likelihood_is_target(self):
        """Tests the acquisition prediction when conditions are met."""
        scan_data = {
            "business_intel": {
                "financials": {"trailingPE": 10},
                "news": {"totalArticles": 20},
            }
        }
        prediction = predict_acquisition_likelihood(scan_data)

        self.assertIsNotNone(prediction)
        self.assertIn("Potential Acquisition Target", prediction.signal)

    def test_predict_acquisition_likelihood_is_not_target(self):
        """Tests the acquisition prediction when conditions are not met."""
        scan_data = {
            "business_intel": {
                "financials": {"trailingPE": 30},
                "news": {"totalArticles": 5},
            }
        }
        prediction = predict_acquisition_likelihood(scan_data)

        self.assertIsNone(prediction)

    @patch("chimera_intel.core.forecaster.joblib.dump")
    @patch("chimera_intel.core.forecaster.get_scan_history")
    def test_train_breach_prediction_model_success(
        self, mock_get_history, mock_joblib_dump
    ):
        """Tests that the breach prediction model training process runs and saves a model."""
        # Arrange: Create mock scan data that can be featurized

        mock_get_history.return_value = [
            {
                "target": "companya.com",
                "timestamp": "2025-01-01T12:00:00Z",
                "scan_data": {
                    "vulnerability_scanner": {"scanned_hosts": [1, 2, 3]},
                    "defensive_breaches": {"breaches": []},
                },
            },
            {
                "target": "companya.com",
                "timestamp": "2025-02-01T12:00:00Z",
                "scan_data": {
                    "defensive_breaches": {
                        "breaches": ["new_breach"]
                    }  # This creates a label for the previous scan
                },
            },
            {
                "target": "companyb.com",
                "timestamp": "2025-01-01T12:00:00Z",
                "scan_data": {"defensive_breaches": {"breaches": []}},
            },
        ]

        # Act

        train_breach_prediction_model()

        # Assert

        mock_get_history.assert_called_once()
        mock_joblib_dump.assert_called_once()
        # Check that the first argument is a trained model

        self.assertIsInstance(mock_joblib_dump.call_args[0][0], RandomForestClassifier)
        # Check that the second argument is the correct filename

        self.assertEqual(mock_joblib_dump.call_args[0][1], "breach_model.pkl")

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

    @patch("chimera_intel.core.forecaster.train_breach_prediction_model")
    def test_cli_train_breach_model_command(self, mock_train_model):
        """Tests that the 'train-breach-model' CLI command calls the correct function."""
        # Act

        result = runner.invoke(app, ["analysis", "forecast", "train-breach-model"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_train_model.assert_called_once()


if __name__ == "__main__":
    unittest.main()
