import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
import os

from chimera_intel.core.appint import analyze_apk_static, appint_app
from chimera_intel.core.schemas import StaticAppAnalysisResult

runner = CliRunner()


class TestAppint(unittest.TestCase):
    """Test cases for the Appint module."""

    @patch("chimera_intel.core.appint.subprocess.run")
    def test_analyze_apk_static_success(self, mock_subprocess_run):
        """Tests successful static analysis of an APK file."""
        # Arrange

        mock_subprocess_run.return_value = MagicMock(check=True, stdout="", stderr="")
        # Create a dummy file for the test

        dummy_filepath = "dummy.apk"
        with open(dummy_filepath, "w") as f:
            f.write("dummy content")
        # Act

        result = analyze_apk_static(dummy_filepath)

        # Assert

        self.assertIsInstance(result, StaticAppAnalysisResult)
        self.assertIsNone(result.error)

        # Clean up the dummy file

        os.remove(dummy_filepath)

    def test_analyze_apk_static_file_not_found(self):
        """Tests the function's behavior when the APK file is not found."""
        # Act

        result = analyze_apk_static("nonexistent.apk")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("APK file not found.", result.error)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.appint.save_scan_to_db")
    @patch("chimera_intel.core.utils.save_or_print_results")
    @patch("chimera_intel.core.appint.analyze_apk_static")
    def test_cli_static_analysis_success(
        self, mock_analyze_apk, mock_save_print, mock_save_db
    ):
        """Tests a successful run of the 'static' CLI command."""
        # Arrange

        mock_analyze_apk.return_value = StaticAppAnalysisResult(
            file_path="test.apk", secrets_found=[]
        )
        # Ensure mocked functions don't raise exceptions

        mock_save_print.return_value = None
        mock_save_db.return_value = None

        # Create a dummy file to simulate its existence

        dummy_filepath = "test.apk"
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

        # Clean up the dummy file

        os.remove(dummy_filepath)

    @patch("chimera_intel.core.appint.save_scan_to_db")
    @patch("chimera_intel.core.utils.save_or_print_results")
    @patch("chimera_intel.core.appint.analyze_apk_static")
    def test_cli_static_analysis_file_not_found(
        self, mock_analyze_apk, mock_save_print, mock_save_db
    ):
        """Tests the 'static' CLI command when the file is not found."""
        # Arrange

        mock_analyze_apk.return_value = StaticAppAnalysisResult(
            file_path="nonexistent.apk", error="APK file not found."
        )
        # Ensure mocked functions don't raise exceptions

        mock_save_print.return_value = None
        mock_save_db.return_value = None

        # Act

        result = runner.invoke(appint_app, ["static", "nonexistent.apk"])

        # Assert

        self.assertEqual(
            result.exit_code, 0, f"CLI command failed with output: {result.stdout}"
        )
        mock_analyze_apk.assert_called_with("nonexistent.apk")
        mock_save_print.assert_called_once()

        # The CLI command prints the result, which contains the error message.
        # So we check the result's stdout.

        self.assertIn("APK file not found.", result.stdout)


if __name__ == "__main__":
    unittest.main()
