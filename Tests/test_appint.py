import unittest
from unittest.mock import patch, MagicMock  # Import MagicMock
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

    @patch("chimera_intel.core.appint.save_scan_to_db")
    # FIX: Patch where the function is *used* (in the appint module)
    @patch("chimera_intel.core.appint.save_or_print_results")
    @patch("chimera_intel.core.appint.analyze_apk_static")
    # FIX: Patch the console to prevent unhandled exceptions
    @patch("chimera_intel.core.appint.console.print")
    def test_cli_static_analysis_success(
        self, mock_console_print, mock_analyze_apk, mock_save_print, mock_save_db
    ):
        """Tests a successful run of the 'static' CLI command."""
        # Arrange
        mock_analyze_apk.return_value = StaticAppAnalysisResult(
            file_path="test.apk", secrets_found=[]
        )
        mock_save_print.return_value = None
        mock_save_db.return_value = None

        dummy_filepath = "test.apk"
        try:
            with open(dummy_filepath, "w") as f:
                f.write("dummy apk content")
            
            # Act
            result = runner.invoke(appint_app, ["static", dummy_filepath])

            # Assert
            self.assertEqual(
                result.exit_code, 0, f"CLI command failed with output: {result.stdout}"
            )
            mock_analyze_apk.assert_called_with(dummy_filepath)
            mock_save_print.assert_called_once()
            mock_save_db.assert_called_once()
        
        finally:
            # Clean up
            if os.path.exists(dummy_filepath):
                os.remove(dummy_filepath)

    @patch("chimera_intel.core.appint.save_scan_to_db")
    # FIX: Patch where the function is *used* (in the appint module)
    @patch("chimera_intel.core.appint.save_or_print_results")
    @patch("chimera_intel.core.appint.analyze_apk_static")
    # FIX: Patch the console to prevent unhandled exceptions
    @patch("chimera_intel.core.appint.console.print")
    def test_cli_static_analysis_file_not_found(
        self, mock_console_print, mock_analyze_apk, mock_save_print, mock_save_db
    ):
        """Tests the 'static' CLI command when the file is not found."""
        # Arrange
        mock_analyze_apk.return_value = StaticAppAnalysisResult(
            file_path="nonexistent.apk", error="APK file not found."
        )
        mock_save_print.return_value = None
        mock_save_db.return_value = None

        # Act
        result = runner.invoke(appint_app, ["static", "nonexistent.apk"])

        # Assert
        self.assertEqual(
            result.exit_code, 1, f"CLI command failed with output: {result.stdout}"
        )
        mock_analyze_apk.assert_called_with("nonexistent.apk")
        
        # FIX: Check that the correct error message was passed to the mocked console
        mock_console_print.assert_called_with(
            "[red]Static analysis failed: APK file not found.[/red]"
        )
        # The other functions should not be called on failure
        mock_save_print.assert_not_called()
        mock_save_db.assert_not_called()


if __name__ == "__main__":
    unittest.main()