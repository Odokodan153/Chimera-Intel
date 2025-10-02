import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
import typer
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from datetime import datetime, timedelta

# Import the specific Typer app for this module, not the main one


from chimera_intel.core.forecaster import forecast_app
from chimera_intel.core.forecaster import (
    run_prediction_rules,
    predict_breach_likelihood,
    predict_acquisition_likelihood,
    check_for_missed_events,
    train_breach_prediction_model,
)

runner = CliRunner()


class TestForecaster(unittest.TestCase):
    """Test cases for the forecaster module."""

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
        historical_data = [
            {
                "scan_data": {
                    "business_intel": {"financials": {"companyName": "TestCorp"}}
                },
                "timestamp": datetime.now() - timedelta(days=100),
            }
        ]
        missed = check_for_missed_events(
            "example.com", historical_data, "business_intel"
        )
        self.assertEqual(len(missed), 1)
        self.assertIn("was not observed in the last 95 days", missed[0])

    def test_check_for_missed_events_not_missed(self):
        """Tests that a recent event is not flagged as missed."""
        historical_data = [
            {
                "scan_data": {
                    "business_intel": {"financials": {"companyName": "TestCorp"}}
                },
                "timestamp": datetime.now() - timedelta(days=30),
            }
        ]
        missed = check_for_missed_events(
            "example.com", historical_data, "business_intel"
        )
        self.assertEqual(len(missed), 0)

    def test_check_for_missed_events_no_prior_data(self):
        """Tests that no missed events are flagged if no prior occurrences exist."""
        historical_data = [
            {
                "scan_data": {"some_other_module": {"data": "value"}},
                "timestamp": datetime.now() - timedelta(days=100),
            }
        ]
        missed = check_for_missed_events(
            "example.com", historical_data, "business_intel"
        )
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
        # FIX: Expanded the mock data to have more samples to avoid the train_test_split error.

        mock_get_history.return_value = [
            {
                "target": "companya.com",
                "timestamp": datetime(2025, 1, 1),
                "scan_data": {"defensive_breaches": {"breaches": []}},
            },
            {
                "target": "companya.com",
                "timestamp": datetime(2025, 2, 1),
                "scan_data": {"defensive_breaches": {"breaches": ["new_breach"]}},
            },
            {
                "target": "companyb.com",
                "timestamp": datetime(2025, 1, 1),
                "scan_data": {"defensive_breaches": {"breaches": []}},
            },
            {
                "target": "companyb.com",
                "timestamp": datetime(2025, 3, 1),
                "scan_data": {"defensive_breaches": {"breaches": ["another_breach"]}},
            },
            # Add more data points to ensure the test set is large enough
            {
                "target": "companyc.com",
                "timestamp": datetime(2025, 1, 1),
                "scan_data": {"defensive_breaches": {"breaches": []}},
            },
            {
                "target": "companyc.com",
                "timestamp": datetime(2025, 2, 1),
                "scan_data": {"defensive_breaches": {"breaches": []}},
            },
            {
                "target": "companyd.com",
                "timestamp": datetime(2025, 1, 1),
                "scan_data": {"defensive_breaches": {"breaches": []}},
            },
            {
                "target": "companyd.com",
                "timestamp": datetime(2025, 4, 1),
                "scan_data": {"defensive_breaches": {"breaches": ["breach3"]}},
            },
            {
                "target": "companye.com",
                "timestamp": datetime(2025, 1, 1),
                "scan_data": {"defensive_breaches": {"breaches": []}},
            },
            {
                "target": "companye.com",
                "timestamp": datetime(2025, 5, 1),
                "scan_data": {"defensive_breaches": {"breaches": ["breach4"]}},
            },
        ]
        train_breach_prediction_model()
        mock_get_history.assert_called_once()
        mock_joblib_dump.assert_called_once()
        self.assertIsInstance(mock_joblib_dump.call_args[0][0], RandomForestClassifier)
        self.assertEqual(mock_joblib_dump.call_args[0][1], "breach_model.pkl")

    # --- CLI Tests ---

    @patch("chimera_intel.core.forecaster.resolve_target")
    @patch("chimera_intel.core.forecaster.get_all_scans_for_target")
    def test_cli_forecast_with_project(self, mock_get_scans, mock_resolve_target):
        """Tests the CLI command using the centralized target resolver."""
        mock_resolve_target.return_value = "project.com"
        mock_get_scans.return_value = []
        result = runner.invoke(forecast_app, ["run", "footprint"])
        self.assertEqual(result.exit_code, 0)
        mock_resolve_target.assert_called_once_with(None, required_assets=["domain"])
        mock_get_scans.assert_called_with("project.com", "footprint")

    @patch("chimera_intel.core.forecaster.resolve_target")
    def test_cli_forecast_resolver_fails(self, mock_resolve_target):
        """Tests the CLI command when the resolver raises an exit exception."""
        mock_resolve_target.side_effect = typer.Exit(code=1)
        result = runner.invoke(forecast_app, ["run", "footprint"])
        self.assertEqual(result.exit_code, 1)

    @patch("chimera_intel.core.forecaster.train_breach_prediction_model")
    def test_cli_train_breach_model_command(self, mock_train_model):
        """Tests that the 'train-breach-model' CLI command calls the correct function."""
        result = runner.invoke(forecast_app, ["train-breach-model"])
        self.assertEqual(result.exit_code, 0)
        mock_train_model.assert_called_once()


if __name__ == "__main__":
    unittest.main()
