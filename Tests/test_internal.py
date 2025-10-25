import unittest
import json
from unittest.mock import patch, mock_open, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.internal import (
    analyze_log_file,
    perform_static_analysis,
    parse_mft,
    internal_app,
)
from chimera_intel.core.schemas import (
    LogAnalysisResult,
    StaticAnalysisResult,
    MFTAnalysisResult
)

runner = CliRunner()


class TestInternal(unittest.TestCase):
    """Test cases for the internal analysis and forensics module."""

    # --- Log Analysis Tests ---

    @patch("chimera_intel.core.internal.os.path.exists", return_value=True)
    def test_analyze_log_file_success(self, mock_exists):
        """Tests a successful log file analysis."""
        log_content = (
            "ERROR: Failed login for user admin\nsshd[1234]: authentication failure"
        )
        with patch("builtins.open", mock_open(read_data=log_content)):
            result = analyze_log_file("/fake/log.txt")
        self.assertIsInstance(result, LogAnalysisResult)
        self.assertEqual(result.total_lines_parsed, 2)
        # Corrected assertion: "authentication failure" also counts as a failed login

        self.assertEqual(result.suspicious_events["failed_login"], 2)
        self.assertEqual(result.suspicious_events["ssh_bruteforce"], 1)
        self.assertEqual(result.suspicious_events["error_spike"], 1)
        self.assertIsNone(result.error)

    @patch("os.path.exists", return_value=False)
    def test_analyze_log_file_not_found(self, mock_exists):
        """Tests log analysis when the file is not found."""
        result = analyze_log_file("/fake/nonexistent.log")
        self.assertIsNotNone(result.error)
        self.assertIn("Log file not found", result.error)

    # --- Static Analysis Tests ---

    @patch("os.path.exists", return_value=True)
    def test_perform_static_analysis_success(self, mock_exists):
        """Tests a successful static analysis of a file."""
        file_content = b"This is a test file with some strings."
        with patch("builtins.open", mock_open(read_data=file_content)):
            result = perform_static_analysis("test.exe")
        self.assertIsInstance(result, StaticAnalysisResult)
        self.assertEqual(result.filename, "test.exe")
        self.assertEqual(result.file_size, len(file_content))
        self.assertIn("md5", result.hashes)
        self.assertIn("sha256", result.hashes)
        self.assertIn("test file", result.embedded_strings[0])
        self.assertIsNone(result.error)

    # --- MFT Analysis Tests ---

    # --- FIX: Added patch for MFT_AVAILABLE boolean guard ---
    @patch("chimera_intel.core.internal.MFT_AVAILABLE", True)
    # --- END FIX ---
    @patch("chimera_intel.core.internal.analyzeMFT", autospec=True)
    @patch("chimera_intel.core.internal.os.path.exists", return_value=True)
    @patch("chimera_intel.core.internal.os.remove")
    def test_parse_mft_success(
        self, mock_remove, mock_exists, mock_analyzeMFT, mock_mft_available
    ):
        """Tests a successful MFT parsing."""
        # Arrange
        mock_analyzeMFT.main = MagicMock(return_value=None)

        mft_csv_output = (
            "Record Number,Filename,Created,Last Modified,is_directory\n"
            "123,test.txt,2023-01-01,2023-01-02,false\n"
        )

        # This mock setup for csv.DictReader is correct.
        m = mock_open()
        with patch("builtins.open", m):
            # Configure the mock file handle (m.return_value) to correctly handle iteration.
            m.return_value.__iter__ = lambda: iter(mft_csv_output.splitlines())

            # Act
            result = parse_mft("/fake/MFT")

        # Assert
        self.assertIsInstance(result, MFTAnalysisResult)
        self.assertEqual(result.total_records, 1)  # This should now pass
        self.assertEqual(result.entries[0].filename, "test.txt")
        self.assertFalse(result.entries[0].is_directory)
        mock_remove.assert_called_once()  # Check that the temp file was cleaned up

    def test_parse_mft_library_not_available(self):
        """Tests MFT parsing when the analyzeMFT library is not installed."""
        with patch("chimera_intel.core.internal.MFT_AVAILABLE", False):
            result = parse_mft("/fake/MFT")
            self.assertIsNotNone(result.error)
            self.assertIn("'analyzeMFT' library not installed", result.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.internal.analyze_log_file")
    def test_cli_analyze_log_success(self, mock_analyze):
        """Tests the 'internal analyze-log' CLI command."""
        mock_analyze.return_value = LogAnalysisResult(
            total_lines_parsed=100, suspicious_events={"failed_login": 5}
        )
        result = runner.invoke(internal_app, ["analyze-log", "test.log"])

        self.assertEqual(result.exit_code, 0, msg=result.output)
        output = json.loads(result.stdout)
        self.assertEqual(output["total_lines_parsed"], 100)
        self.assertEqual(output["suspicious_events"]["failed_login"], 5)

    @patch("chimera_intel.core.internal.perform_static_analysis")
    def test_cli_static_analysis_success(self, mock_analyze):
        """Tests the 'internal static-analysis' CLI command."""
        mock_analyze.return_value = StaticAnalysisResult(
            filename="test.exe", file_size=1024, hashes={}, embedded_strings=[]
        )
        result = runner.invoke(internal_app, ["static-analysis", "test.exe"])

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn('"filename": "test.exe"', result.stdout)

    @patch("chimera_intel.core.internal.parse_mft")
    def test_cli_parse_mft_success(self, mock_parse):
        """Tests the 'internal parse-mft' CLI command."""
        mock_parse.return_value = MFTAnalysisResult(total_records=1, entries=[])
        result = runner.invoke(internal_app, ["parse-mft", "$MFT"])

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn('"total_records": 1', result.stdout)


if __name__ == "__main__":
    unittest.main()