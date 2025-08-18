import unittest
from unittest.mock import patch, mock_open
from chimera_intel.core.reporter import generate_pdf_report, create_pdf_report


class TestReporter(unittest.TestCase):
    """Test cases for the reporter module."""

    @patch("chimera_intel.core.reporter.SimpleDocTemplate")
    @patch("chimera_intel.core.reporter.Paragraph")
    @patch("chimera_intel.core.reporter.Spacer")
    @patch("chimera_intel.core.reporter.Table")
    def test_generate_pdf_report_success(
        self, mock_table, mock_spacer, mock_paragraph, mock_doc
    ):
        """Tests a successful PDF report generation."""
        mock_doc_instance = mock_doc.return_value

        test_data = {
            "domain": "example.com",
            "footprint": {
                "subdomains": {
                    "results": [
                        {
                            "domain": "sub.example.com",
                            "confidence": "HIGH",
                            "sources": ["test"],
                        }
                    ]
                }
            },
        }

        generate_pdf_report(test_data, "test_report.pdf")

        # Verify that the document was created and built

        mock_doc.assert_called_with("test_report.pdf")
        self.assertTrue(mock_doc_instance.build.called)

        # Verify that a table was created for the subdomain data

        mock_table.assert_called()

    @patch("chimera_intel.core.reporter.SimpleDocTemplate")
    def test_generate_pdf_report_exception(self, mock_doc):
        """Tests PDF generation when an unexpected error occurs."""
        # Make the build method raise an exception

        mock_doc.return_value.build.side_effect = Exception("Failed to write PDF")

        # The function should catch the exception and log an error, not crash

        with patch("logging.Logger.error") as mock_logger_error:
            generate_pdf_report({}, "test.pdf")
            mock_logger_error.assert_called_once()
            self.assertIn(
                "An error occurred during PDF generation",
                mock_logger_error.call_args[0][0],
            )

    @patch(
        "builtins.open", new_callable=mock_open, read_data='{"domain": "example.com"}'
    )
    @patch("chimera_intel.core.reporter.generate_pdf_report")
    def test_create_pdf_report_command_success(self, mock_generate_pdf, mock_file):
        """Tests the CLI command function for creating a PDF report."""
        create_pdf_report(json_file="test.json", output_file="output.pdf")

        mock_file.assert_called_with("test.json", "r", encoding="utf-8")
        mock_generate_pdf.assert_called_once_with(
            {"domain": "example.com"}, "output.pdf"
        )

    @patch(
        "builtins.open", new_callable=mock_open, read_data='{"domain": "example.com"}'
    )
    @patch("chimera_intel.core.reporter.generate_pdf_report")
    def test_create_pdf_report_command_no_output_file(
        self, mock_generate_pdf, mock_file
    ):
        """Tests the CLI command when no output file is specified."""
        create_pdf_report(json_file="test.json", output_file=None)

        # Verify it generates a default filename based on the target

        expected_output_path = "example_com.pdf"
        mock_generate_pdf.assert_called_once_with(
            {"domain": "example.com"}, expected_output_path
        )


if __name__ == "__main__":
    unittest.main()
