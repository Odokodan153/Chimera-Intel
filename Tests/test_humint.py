import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.humint import (
    add_humint_source,
    add_humint_report,
    analyze_humint_reports,
    humint_app,
)
from chimera_intel.core.schemas import SWOTAnalysisResult

runner = CliRunner()


class TestHumint(unittest.TestCase):
    """Test cases for the Human Intelligence (HUMINT) module."""

    # --- Function Tests ---

    @patch("chimera_intel.core.humint.get_db_connection")
    def test_add_humint_source_success(self, mock_get_conn):
        """Tests successfully adding a new HUMINT source."""
        # Arrange

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        # Act

        add_humint_source("ALPHA", "A1", "Cybercrime")

        # Assert

        mock_cursor.execute.assert_called_once_with(
            "INSERT INTO humint_sources (name, reliability, expertise) VALUES (%s, %s, %s)",
            ("ALPHA", "A1", "Cybercrime"),
        )
        mock_conn.commit.assert_called_once()

    @patch("chimera_intel.core.humint.get_db_connection")
    def test_add_humint_report_success(self, mock_get_conn):
        """Tests successfully adding a new HUMINT report."""
        # Arrange

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        # Simulate finding the source in the database

        mock_cursor.fetchone.return_value = (1,)  # (source_id,)
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        # Act

        add_humint_report("ALPHA", "Target is planning a new product launch.")

        # Assert

        mock_cursor.execute.assert_any_call(
            "SELECT id FROM humint_sources WHERE name = %s", ("ALPHA",)
        )
        mock_cursor.execute.assert_any_call(
            "INSERT INTO humint_reports (source_id, content) VALUES (%s, %s)",
            (1, "Target is planning a new product launch."),
        )
        mock_conn.commit.assert_called_once()

    @patch("chimera_intel.core.humint.get_db_connection")
    def test_add_humint_report_source_not_found(self, mock_get_conn):
        """Tests adding a report when the specified source does not exist."""
        # Arrange

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        # Simulate not finding the source

        mock_cursor.fetchone.return_value = None
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        # Act

        add_humint_report("BETA", "Some report content.")

        # Assert
        # Ensure no INSERT statement for the report was ever called

        insert_calls = [
            call
            for call in mock_cursor.execute.call_args_list
            if "INSERT" in call[0][0]
        ]
        self.assertEqual(len(insert_calls), 0)
        mock_conn.commit.assert_not_called()

    @patch("chimera_intel.core.humint.generate_swot_from_data")
    @patch("chimera_intel.core.humint.get_db_connection")
    @patch("chimera_intel.core.humint.API_KEYS")
    def test_analyze_humint_reports_success(
        self, mock_api_keys, mock_get_conn, mock_gen_swot
    ):
        """Tests successful AI analysis of HUMINT reports."""
        # Arrange

        mock_api_keys.google_api_key = "fake_key"
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            ("ALPHA", "A1", "Report content about topic.")
        ]
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_gen_swot.return_value = SWOTAnalysisResult(analysis_text="AI Summary Text")

        # Act

        result = analyze_humint_reports("topic")

        # Assert

        self.assertEqual(result, "AI Summary Text")
        mock_gen_swot.assert_called_once()
        # Check that the prompt contains the fetched report

        prompt_arg = mock_gen_swot.call_args[0][0]
        self.assertIn("Report content about topic.", prompt_arg)

    # --- CLI Tests ---

    @patch("chimera_intel.core.humint.add_humint_source")
    def test_cli_add_source(self, mock_add_source):
        """Tests the 'humint add-source' CLI command."""
        result = runner.invoke(
            humint_app,
            [
                "add-source",
                "--name",
                "CHARLIE",
                "--reliability",
                "B2",
                "--expertise",
                "Finance",
            ],
        )
        self.assertEqual(result.exit_code, 0)
        mock_add_source.assert_called_once_with("CHARLIE", "B2", "Finance")

    @patch("chimera_intel.core.humint.add_humint_report")
    def test_cli_add_report(self, mock_add_report):
        """Tests the 'humint add-report' CLI command."""
        result = runner.invoke(
            humint_app,
            ["add-report", "--source", "ALPHA", "--content", "New intel"],
        )
        self.assertEqual(result.exit_code, 0)
        mock_add_report.assert_called_once_with("ALPHA", "New intel")

    @patch("chimera_intel.core.humint.analyze_humint_reports")
    def test_cli_analyze(self, mock_analyze):
        """Tests the 'humint analyze' CLI command."""
        mock_analyze.return_value = "AI-Powered Analysis"
        result = runner.invoke(humint_app, ["analyze", "acquisition"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("AI-Powered Analysis", result.stdout)
        mock_analyze.assert_called_once_with("acquisition")


if __name__ == "__main__":
    unittest.main()
