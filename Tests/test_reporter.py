import unittest
from unittest.mock import patch, mock_open
from chimera_intel.core.reporter import (
    generate_pdf_report,
    create_pdf_report,
    generate_graph_report,
    generate_threat_briefing,
    create_briefing_report
)
from reportlab.lib.pagesizes import letter  # type: ignore

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
    
    @patch("chimera_intel.core.reporter.BaseDocTemplate")
    @patch("chimera_intel.core.reporter.Paragraph")
    @patch("chimera_intel.core.reporter.Spacer")
    def test_generate_threat_briefing_success(
        self, mock_spacer, mock_paragraph, mock_doc
    ):
        """Tests a successful threat briefing generation."""
        mock_doc_instance = mock_doc.return_value

        # Data now reflects the aggregated format
        test_data = {
            "target": "example.com",
            "modules": {
                "vulnerability_scanner": {
                    "scanned_hosts": [
                        {
                            "host": "1.2.3.4",
                            "open_ports": [
                                {
                                    "port": 443,
                                    "vulnerabilities": [
                                        {"id": "CVE-2023-1234", "cvss_score": 9.8}
                                    ],
                                }
                            ],
                        }
                    ]
                },
                "defensive_breaches": {
                    "hibp": {"breaches": [{"Name": "Breach1"}]}
                },
                "footprint": {
                    "subdomains": {"total_unique": 50},
                    "dns_records": {"A": ["1.2.3.4"]}
                }
            }
        }

        generate_threat_briefing(test_data, "test_briefing.pdf")

        mock_doc.assert_called_with("test_briefing.pdf", pagesize=letter)
        self.assertTrue(mock_doc_instance.build.called)
        
        # Check that critical findings were processed
        calls = mock_paragraph.call_args_list
        call_texts = [call[0][0] for call in calls]
        
        self.assertIn("Executive Threat Briefing", call_texts)
        self.assertIn("Target: example.com", call_texts)
        self.assertIn("• <b>Critical CVE:</b> CVE-2023-1234 (Score: 9.8) on 1.2.3.4:443", call_texts)
        self.assertIn("• <b>Data Breaches:</b> Target associated with 1 known breaches.", call_texts)
        self.assertIn("• <b>50</b> subdomains and <b>1</b> unique IP addresses identified.", call_texts)
        self.assertIn("• <b>Patching:</b> Immediately address all Critical (9.0+) CVEs identified.", call_texts)

    # --- MODIFIED TEST ---
    @patch(
        "builtins.open", new_callable=mock_open, read_data='{"domain": "example.com"}'
    )
    @patch("chimera_intel.core.reporter.generate_threat_briefing")
    @patch("chimera_intel.core.reporter.get_aggregated_data_for_target") # <-- MOCK THE DB CALL
    def test_create_briefing_report_command(
        self, mock_get_aggregated_data, mock_generate_briefing, mock_file
    ):
        """Tests the CLI command function for creating a briefing."""
        
        # --- Arrange ---
        # Mock the aggregated data returned from the DB
        aggregated_data = {
            "target": "example.com",
            "modules": {"footprint": {"subdomains": {"total_unique": 10}}}
        }
        mock_get_aggregated_data.return_value = aggregated_data

        # --- Act ---
        create_briefing_report(json_file="test.json", output_file="briefing.pdf")

        # --- Assert ---
        # 1. Check that the JSON file was opened to get the target
        mock_file.assert_called_with("test.json", "r", encoding="utf-8")
        
        # 2. Check that the DB was called with the target from the file
        mock_get_aggregated_data.assert_called_once_with("example.com")
        
        # 3. Check that the PDF generator was called with the *aggregated* data
        mock_generate_briefing.assert_called_once_with(
            aggregated_data, "briefing.pdf"
        )

if __name__ == "__main__":
    unittest.main()
