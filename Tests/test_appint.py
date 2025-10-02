import unittest
from unittest.mock import patch, mock_open, MagicMock

from chimera_intel.core.appint import analyze_apk_static
from chimera_intel.core.schemas import StaticAppAnalysisResult


class TestAppint(unittest.TestCase):
    """Test cases for the Mobile Application Intelligence (APPINT) module."""

    @patch("chimera_intel.core.appint.shutil.rmtree")
    @patch("chimera_intel.core.appint.subprocess.run")
    @patch("chimera_intel.core.appint.os.path.exists", return_value=True)
    def test_analyze_apk_static_success(
        self, mock_exists, mock_subprocess, mock_rmtree
    ):
        """Tests a successful static analysis where secrets are found."""
        # Arrange

        mock_subprocess.return_value = MagicMock(check_returncode=lambda: None)

        # Mock the file system walk to find a file with a secret

        mock_file_content = 'this is a test line with an api_key = "ABCDEFG12345HIJKLM"'

        with patch("os.walk") as mock_walk:
            mock_walk.return_value = [("decompiled/res", [], ["strings.xml"])]
            with patch("builtins.open", mock_open(read_data=mock_file_content)):
                # Act

                result = analyze_apk_static("test.apk")
        # Assert

        self.assertIsInstance(result, StaticAppAnalysisResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.secrets_found), 1)
        self.assertEqual(result.secrets_found[0].secret_type, "api_key")
        mock_subprocess.assert_called_once()
        mock_rmtree.assert_called_once()  # Verify cleanup

    @patch("chimera_intel.core.appint.shutil.rmtree")
    @patch("chimera_intel.core.appint.subprocess.run")
    @patch("chimera_intel.core.appint.os.path.exists")
    def test_analyze_apk_static_apktool_not_found(
        self, mock_exists, mock_subprocess, mock_rmtree
    ):
        """Tests the error handling when apktool is not installed."""
        # Arrange
        # Simulate that the input APK exists, but the output directory is never created.

        def exists_side_effect(path):
            return path == "test.apk"

        mock_exists.side_effect = exists_side_effect
        mock_subprocess.side_effect = FileNotFoundError

        # Act

        result = analyze_apk_static("test.apk")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("apktool not found", result.error)
        # Ensure cleanup is not called if the directory was never created

        mock_rmtree.assert_not_called()

    @patch("chimera_intel.core.appint.os.path.exists", return_value=False)
    def test_analyze_apk_static_file_not_found(self, mock_exists):
        """Tests the error handling when the target APK file does not exist."""
        # Act

        result = analyze_apk_static("nonexistent.apk")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("APK file not found", result.error)


if __name__ == "__main__":
    unittest.main()
