import unittest
from unittest.mock import patch, MagicMock
from httpx import Response, RequestError
from typer.testing import CliRunner

from chimera_intel.cli import app
from chimera_intel.core.signal_analyzer import (
    scrape_job_postings,
    analyze_signals,
)
from chimera_intel.core.schemas import JobPostingsResult, StrategicSignal

runner = CliRunner(mix_stderr=False)


class TestSignalAnalyzer(unittest.TestCase):
    """
    Extended test cases for the signal_analyzer module.
    """

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_scrape_job_postings_success_on_first_url(self, mock_get):
        """
        Tests a successful job posting scrape from the first attempted URL.
        """
        # --- Arrange ---

        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        # Simulate a realistic HTML structure with a job title

        mock_response.text = '<html><body><a class="job-opening-link">Senior Data Scientist</a></body></html>'
        mock_get.return_value = mock_response

        # --- Act ---

        result = scrape_job_postings("example.com")

        # --- Assert ---

        self.assertIsInstance(result, JobPostingsResult)
        self.assertEqual(len(result.job_postings), 1)
        self.assertIn("Senior Data Scientist", result.job_postings)
        self.assertIsNone(result.error)
        # Ensure it only tried the first URL and then stopped

        mock_get.assert_called_once()

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_scrape_job_postings_success_on_fallback_url(self, mock_get):
        """
        Tests that the scraper correctly tries the next URL if the first one fails.
        """
        # --- Arrange ---
        # First call will be a 404, second will be a success

        mock_fail_response = MagicMock(spec=Response, status_code=404)
        mock_success_response = MagicMock(spec=Response, status_code=200)
        mock_success_response.text = (
            '<html><body><h2 class="job">Backend Engineer (Go)</h2></body></html>'
        )
        mock_get.side_effect = [mock_fail_response, mock_success_response]

        # --- Act ---

        result = scrape_job_postings("example.com")

        # --- Assert ---

        self.assertEqual(len(result.job_postings), 1)
        self.assertIn("Backend Engineer (Go)", result.job_postings)
        # Verify it was called twice (first URL failed, second succeeded)

        self.assertEqual(mock_get.call_count, 2)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_scrape_job_postings_all_urls_fail(self, mock_get):
        """
        Tests the behavior when all potential job page URLs result in errors.
        """
        # --- Arrange ---
        # Simulate network errors for all attempts

        mock_get.side_effect = RequestError("Connection failed")

        # --- Act ---

        result = scrape_job_postings("example.com")

        # --- Assert ---

        self.assertEqual(len(result.job_postings), 0)
        # It should try all available URLs before giving up

        self.assertGreaterEqual(mock_get.call_count, 2)

    def test_analyze_signals_multiple_sources(self):
        """
        Tests the analysis engine when signals are present in both tech stack and job postings.
        """
        # --- Arrange ---

        aggregated_data = {
            "modules": {
                "web_analyzer": {
                    "web_analysis": {
                        "tech_stack": {"results": [{"technology": "Salesforce CRM"}]}
                    }
                }
            },
            "job_postings": {
                "job_postings": [
                    "Hiring: Head of People and Culture",
                    "Senior Terraform Engineer",
                ]
            },
        }

        # --- Act ---

        signals = analyze_signals(aggregated_data)

        # --- Assert ---

        self.assertEqual(len(signals), 3)
        categories = {s.category for s in signals}
        self.assertIn("Marketing & Sales", categories)
        self.assertIn("HR & Culture", categories)
        self.assertIn("Technology & Engineering", categories)

    def test_analyze_signals_no_relevant_data(self):
        """
        Tests that no signals are generated when the data contains no keywords.
        """
        # --- Arrange ---

        aggregated_data = {
            "modules": {
                "web_analyzer": {
                    "web_analysis": {
                        "tech_stack": {"results": [{"technology": "React"}]}
                    }
                }
            },
            "job_postings": {"job_postings": ["Frontend Developer"]},
        }

        # --- Act ---

        signals = analyze_signals(aggregated_data)

        # --- Assert ---

        self.assertEqual(len(signals), 0)

    @patch("chimera_intel.core.signal_analyzer.get_aggregated_data_for_target")
    @patch("chimera_intel.core.signal_analyzer.scrape_job_postings")
    def test_cli_signal_analysis_command_success(self, mock_scrape, mock_get_data):
        """
        Tests a successful run of the `analysis signal run` CLI command.
        """
        # --- Arrange ---

        mock_get_data.return_value = {"modules": {}}
        mock_scrape.return_value = JobPostingsResult(
            job_postings=["Hiring for Data Scientist"]
        )

        # --- Act ---

        result = runner.invoke(app, ["analysis", "signal", "run", "example.com"])

        # --- Assert ---

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Potential Strategic Signals Detected", result.stdout)
        self.assertIn("Technology & Engineering", result.stdout)
        mock_get_data.assert_called_once_with("example.com")
        mock_scrape.assert_called_once_with("example.com")

    def test_cli_signal_analysis_invalid_domain(self):
        """
        Tests that the CLI command exits with an error for an invalid domain format.
        """
        # --- Act ---

        result = runner.invoke(app, ["analysis", "signal", "run", "invalid-domain"])

        # --- Assert ---

        self.assertEqual(result.exit_code, 1)
        self.assertIn("is not a valid domain format", result.stdout)

    @patch("chimera_intel.core.signal_analyzer.get_aggregated_data_for_target")
    def test_cli_signal_analysis_no_historical_data(self, mock_get_data):
        """
        Tests the CLI command's graceful exit when no historical data is found.
        """
        # --- Arrange ---

        mock_get_data.return_value = None

        # --- Act ---

        result = runner.invoke(app, ["analysis", "signal", "run", "example.com"])

        # --- Assert ---
        # The command should exit with a non-zero code to indicate no data was found

        self.assertEqual(result.exit_code, 1)
        self.assertNotIn("Potential Strategic Signals Detected", result.stdout)

    @patch("chimera_intel.core.signal_analyzer.get_aggregated_data_for_target")
    @patch("chimera_intel.core.signal_analyzer.scrape_job_postings")
    def test_cli_signal_analysis_no_signals_found(self, mock_scrape, mock_get_data):
        """
        Tests the CLI command's behavior when scans run but no signals are detected.
        """
        # --- Arrange ---

        mock_get_data.return_value = {"modules": {}}
        mock_scrape.return_value = JobPostingsResult(job_postings=["Sales Associate"])

        # --- Act ---

        result = runner.invoke(app, ["analysis", "signal", "run", "example.com"])

        # --- Assert ---
        # The command should exit cleanly

        self.assertEqual(result.exit_code, 0)
        # The results table should not be printed

        self.assertNotIn("Potential Strategic Signals Detected", result.stdout)
        self.assertIn("No strong strategic signals detected", result.stderr)


if __name__ == "__main__":
    unittest.main()
