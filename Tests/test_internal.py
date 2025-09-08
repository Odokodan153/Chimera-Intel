import unittest
from unittest.mock import patch, mock_open
from chimera_intel.core.internal import (
    analyze_log_file,
    perform_static_analysis,
    parse_mft,
)
from chimera_intel.core.schemas import (
    LogAnalysisResult,
    StaticAnalysisResult,
    MFTAnalysisResult,
)


class TestInternal(unittest.TestCase):
    """Test cases for the internal analysis and forensics module."""

    @patch("chimera_intel.core.internal.os.path.exists", return_value=True)
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="""Sep  1 10:00:00 server sshd[1234]: Failed password for invalid user user1 from 1.2.3.4 port 12345 ssh2
Sep  1 10:00:01 server sshd[1234]: error: Received disconnect from 1.2.3.4 port 12345:11: [preauth]
Sep  1 10:00:02 server CRON[5678]: fatal error: another cron daemon is already running""",
    )
    def test_analyze_log_file(self, mock_file, mock_exists):
        """Tests the log analysis function."""
        result = analyze_log_file("/var/log/auth.log")
        self.assertIsInstance(result, LogAnalysisResult)
        self.assertEqual(result.total_lines_parsed, 3)
        self.assertEqual(result.suspicious_events["failed_login"], 1)
        self.assertEqual(result.suspicious_events["ssh_bruteforce"], 2)
        self.assertEqual(result.suspicious_events["error_spike"], 2)
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.internal.os.path.exists", return_value=True)
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=b"some content API_KEY other content",
    )
    def test_perform_static_analysis(self, mock_file, mock_exists):
        """Tests the static file analysis function."""
        result = perform_static_analysis("suspicious.exe")
        self.assertIsInstance(result, StaticAnalysisResult)
        self.assertIn("md5", result.hashes)
        self.assertIn("sha256", result.hashes)
        self.assertIn("API_KEY", result.embedded_strings)
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.internal.os.path.exists", return_value=True)
    @patch("chimera_intel.core.internal.analyzeMFT.main_run")
    def test_parse_mft(self, mock_main_run, mock_exists):
        """Tests the MFT parsing function."""
        mock_main_run.return_value = [
            {
                "record_number": 1,
                "filename": "file1.txt",
                "creation_time": "2023-01-01T12:00:00",
                "modification_time": "2023-01-01T12:00:00",
                "is_directory": False,
            },
            {
                "record_number": 2,
                "filename": "evil.exe",
                "creation_time": "2023-01-01T12:01:00",
                "modification_time": "2023-01-01T12:01:00",
                "is_directory": False,
            },
            {
                "record_number": 3,
                "filename": "folder",
                "creation_time": "2023-01-01T12:02:00",
                "modification_time": "2023-01-01T12:02:00",
                "is_directory": True,
            },
        ]
        result = parse_mft("MFT_dump")
        self.assertIsInstance(result, MFTAnalysisResult)
        self.assertEqual(result.total_records, 3)
        self.assertEqual(result.entries[1].filename, "evil.exe")
        self.assertIsNone(result.error)


if __name__ == "__main__":
    unittest.main()
