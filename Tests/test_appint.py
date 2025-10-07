import unittest
from unittest.mock import patch, mock_open, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.appint import analyze_apk_static, appint_app
from chimera_intel.core.schemas import StaticAppAnalysisResult

runner = CliRunner()


class TestAppint(unittest.TestCase):
    """Test cases for the Mobile Application Intelligence (APPINT) module."""

    @patch("chimera_intel.core.appint.shutil.rmtree")
    @patch("chimera_intel.core.appint.subprocess.run")
    @patch("chimera_intel.core.appint.os.path.exists", return_value=True)
    def test_analyze_apk_static_success_with_secrets(
        self, mock_exists, mock_subprocess, mock_rmtree
    ):
        """Tests a successful static analysis where secrets are found."""
        # Arrange

        mock_subprocess.return_value = MagicMock(check_returncode=lambda: None)
        mock_file_content = 'this is a test line with an api_key = "ABCDEFG12345HIJKLM"'

        # Mock the file system walk to find a file with a secret

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
        self.assertEqual(result.secrets_found[0].rule_id, "generic-secret")
        mock_subprocess.assert_called_once()
        mock_rmtree.assert_called_once()  # Verify cleanup

    @patch("chimera_intel.core.appint.shutil.rmtree")
    @patch("chimera_intel.core.appint.subprocess.run")
    @patch("chimera_intel.core.appint.os.path.exists", return_value=True)
    def test_analyze_apk_static_no_secrets(
        self, mock_exists, mock_subprocess, mock_rmtree
    ):
        """Tests a successful static analysis where no secrets are found."""
        # Arrange

        mock_subprocess.return_value = MagicMock(check_returncode=lambda: None)
        mock_file_content = "this is a clean line of code with no secrets."

        with patch("os.walk") as mock_walk:
            mock_walk.return_value = [("decompiled/res", [], ["strings.xml"])]
            with patch("builtins.open", mock_open(read_data=mock_file_content)):
                # Act

                result = analyze_apk_static("test.apk")
        # Assert

        self.assertIsInstance(result, StaticAppAnalysisResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.secrets_found), 0)  # Should find no secrets
        mock_subprocess.assert_called_once()
        mock_rmtree.assert_called_once()

    @patch("chimera_intel.core.appint.shutil.rmtree")
    @patch("chimera_intel.core.appint.subprocess.run")
    @patch("chimera_intel.core.appint.os.path.exists")
    def test_analyze_apk_static_apktool_not_found(
        self, mock_exists, mock_subprocess, mock_rmtree
    ):
        """Tests the error handling when apktool is not installed."""
        # Arrange
        # Simulate that the input APK exists, but apktool itself is not found.

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

    @patch("chimera_intel.core.appint.shutil.rmtree")
    @patch("chimera_intel.core.appint.subprocess.run")
    @patch("chimera_intel.core.appint.os.path.exists", return_value=True)
    def test_analyze_apk_static_unexpected_error(
        self, mock_exists, mock_subprocess, mock_rmtree
    ):
        """Tests the general exception handling during analysis."""
        # Arrange

        mock_subprocess.side_effect = Exception("An unexpected error occurred")

        # Act

        result = analyze_apk_static("test.apk")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("An unexpected error occurred", result.error)
        # Verify that cleanup is still called even on unexpected errors

        mock_rmtree.assert_called_once()

    # --- CLI COMMAND TESTS ---

    @patch("chimera_intel.core.appint.analyze_apk_static")
    def test_cli_static_analysis_success(self, mock_analyze_apk):
        """Tests the 'appint static' CLI command with a successful run."""
        # Arrange

        mock_analyze_apk.return_value = StaticAppAnalysisResult(
            file_path="test.apk", secrets_found=[]
        )

        # Act

        result = runner.invoke(appint_app, ["static", "test.apk"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn('"file_path": "test.apk"', result.stdout)
        mock_analyze_apk.assert_called_with("test.apk")

    @patch("chimera_intel.core.appint.analyze_apk_static")
    def test_cli_static_analysis_file_not_found(self, mock_analyze_apk):
        """Tests the CLI command when the input APK file does not exist."""
        # Arrange

        mock_analyze_apk.return_value = StaticAppAnalysisResult(
            file_path="nonexistent.apk", error="APK file not found."
        )

        # Act

        result = runner.invoke(appint_app, ["static", "nonexistent.apk"])

        # Assert

        self.assertEqual(
            result.exit_code, 0
        )  # The command itself runs, but prints the error
        self.assertIn("APK file not found", result.stdout)


if __name__ == "__main__":
    unittest.main()
