import unittest
from unittest.mock import patch, MagicMock  # Added MagicMock
from typer.testing import CliRunner
import os

from chimera_intel.core.appint import analyze_apk_static, appint_app
from chimera_intel.core.schemas import StaticAppAnalysisResult

runner = CliRunner()


class TestAppint(unittest.TestCase):
    """Test cases for the Appint module."""

    def test_analyze_apk_static_file_not_found(self):
        """Tests the function's behavior when the APK file is not found."""
        # Act
        result = analyze_apk_static("nonexistent.apk")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("APK file not found.", result.error)

    # --- CLI Command Tests ---

    # FIX: Mocks updated based on analysis.
    # We now mock the *dependencies* (os, subprocess, shutil)
    # instead of the function itself (analyze_apk_static)
    # to correctly test the CLI integration and avoid Exit Code 2.
    
    @patch("chimera_intel.core.appint.save_scan_to_db")
    @patch("chimera_intel.core.appint.save_or_print_results")
    @patch("chimera_intel.core.appint.shutil.rmtree")
    @patch("chimera_intel.core.appint.subprocess.run")
    @patch("chimera_intel.core.appint.os.path.exists", return_value=True)
    @patch("chimera_intel.core.appint.console.print")
    def test_cli_static_analysis_success(
        self,
        mock_console_print,
        mock_exists,
        mock_subprocess,
        mock_rmtree,
        mock_save_print,
        mock_save_db,
    ):
        """Tests a successful run of the 'static' CLI command by mocking dependencies."""
        # Arrange
        # Mock subprocess.run to simulate successful decompilation
        mock_subprocess.return_value = MagicMock(stdout="Decompiled", returncode=0)

        # Act
        # We run the command. We don't create a dummy file because os.path.exists is mocked.
        result = runner.invoke(appint_app, ["static", "dummy.apk"])

        # Assert
        self.assertEqual(
            result.exit_code, 0, f"CLI command failed with output: {result.stdout}"
        )
        mock_exists.assert_called_with("dummy.apk")  # Check file path was checked
        mock_subprocess.assert_called_once()  # Check that apktool was called
        mock_save_print.assert_called_once()
        mock_save_db.assert_called_once()
        mock_rmtree.assert_called_once()  # Check cleanup

    # FIX: Mocks updated to target os.path.exists.
    @patch("chimera_intel.core.appint.save_scan_to_db")
    @patch("chimera_intel.core.appint.save_or_print_results")
    @patch("chimera_intel.core.appint.os.path.exists", return_value=False)  # Mock os.path.exists
    @patch("chimera_intel.core.appint.console.print")
    def test_cli_static_analysis_file_not_found(
        self, mock_console_print, mock_exists, mock_save_print, mock_save_db
    ):
        """Tests the 'static' CLI command when the file is not found (mocks os.path.exists)."""
        # Arrange
        # os.path.exists is mocked via decorator to return False

        # Act
        result = runner.invoke(appint_app, ["static", "nonexistent.apk"])

        # Assert
        self.assertEqual(
            result.exit_code, 1, f"CLI command failed with output: {result.stdout}"
        )
        mock_exists.assert_called_with("nonexistent.apk")

        # Check that the correct error message was printed
        # This assumes the CLI function catches the error from analyze_apk_static
        # (which returns an error because mock_exists is False)
        # and prints this specific message.
        mock_console_print.assert_called_with(
            "[red]Static analysis failed: APK file not found.[/red]"
        )
        # The other functions should not be called on failure
        mock_save_print.assert_not_called()
        mock_save_db.assert_not_called()


if __name__ == "__main__":
    unittest.main()