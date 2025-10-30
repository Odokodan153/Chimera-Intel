import unittest
from unittest.mock import patch, mock_open
from chimera_intel.core.reporter import (
    generate_pdf_report,
    create_pdf_report,
    generate_graph_report,
)


class TestReporter(unittest.TestCase):
    """Test cases for the reporter module."""

    @patch("chimera_intel.core.reporter.BaseDocTemplate")
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

        mock_doc.assert_called_with("test_report.pdf")
        self.assertTrue(mock_doc_instance.build.called)
        mock_table.assert_called()

    @patch("chimera_intel.core.reporter.BaseDocTemplate")
    def test_generate_pdf_report_exception(self, mock_doc):
        """Tests PDF generation when an unexpected error occurs."""
        mock_doc.return_value.build.side_effect = Exception("Failed to write PDF")

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
        expected_output_path = "example_com.pdf"
        mock_generate_pdf.assert_called_once_with(
            {"domain": "example.com"}, expected_output_path
        )

    @patch("chimera_intel.core.reporter.BaseDocTemplate")
    @patch("os.path.exists", return_value=True)
    def test_generate_pdf_with_logo(self, mock_exists, mock_doc):
        """Tests that the PDF generator attempts to add a logo if configured."""
        with patch(
            "chimera_intel.core.reporter.CONFIG.reporting.pdf.logo_path", "logo.png"
        ):
            with patch("chimera_intel.core.reporter.Image") as mock_image:
                generate_pdf_report({}, "report.pdf")
                # Check if Image was called with a width in inches (144.0 = 2 * 72)

                mock_image.assert_called_with("logo.png", width=144.0, height=144.0)

    @patch("chimera_intel.core.reporter.build_and_save_graph")
    def test_generate_graph_report_success(self, mock_build_graph):
        """Tests the HTML graph report generation."""
        generate_graph_report("example.com", "graph.html")

        mock_build_graph.assert_called_once_with("example.com", "graph.html")


if __name__ == "__main__":
    unittest.main()
