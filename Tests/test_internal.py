import unittest
from chimera_intel.core.internal import (
    analyze_log_file,
    perform_static_analysis,
    parse_mft,
)


class TestInternal(unittest.TestCase):
    """Test cases for the internal analysis and forensics module."""

    def test_analyze_log_file(self):
        """Tests the log analysis function."""
        result = analyze_log_file("/var/log/auth.log")
        self.assertIsNotNone(result)
        self.assertGreater(result.total_lines_parsed, 0)
        self.assertIn("failed_login", result.suspicious_events)

    def test_perform_static_analysis(self):
        """Tests the static file analysis function."""
        result = perform_static_analysis("suspicious.exe")
        self.assertIsNotNone(result)
        self.assertIn("md5", result.hashes)
        self.assertIn("sha256", result.hashes)
        self.assertIn("API_KEY", result.embedded_strings)

    def test_parse_mft(self):
        """Tests the MFT parsing function."""
        result = parse_mft("MFT_dump")
        self.assertIsNotNone(result)
        self.assertEqual(len(result.entries), 3)
        self.assertEqual(result.entries[1].filename, "evil.exe")


if __name__ == "__main__":
    unittest.main()
