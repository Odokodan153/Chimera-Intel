import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.appint import analyze_apk_static, appint_app

runner = CliRunner()


class TestAppint(unittest.TestCase):
    """Test cases for the Appint module."""

    @patch("chimera_intel.core.appint.os.path.exists", return_value=False)
    def test_analyze_apk_static_file_not_found(self, mock_exists):
        """Tests the function's behavior when the APK file is not found."""
        # Act
        result = analyze_apk_static("nonexistent.apk")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("APK file not found.", result.error)
        mock_exists.assert_called_with("nonexistent.apk")

    # --- CLI Command Tests ---

    # Patches are applied from bottom-up, matching the argument order
    @patch("chimera_intel.core.appint.logger")  # FIX 1: Patch the logger
    @patch("chimera_intel.core.appint.os.walk", return_value=[])  # FIX 2: Mock os.walk
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
        mock_os_walk,  # Argument for new os.walk mock
        mock_logger,   # Argument for new logger mock
    ):
        """Tests a successful run of the 'static' CLI command by mocking dependencies."""
        # Arrange
        # Mock subprocess.run to simulate successful decompilation
        mock_subprocess.return_value = MagicMock(stdout="Decompiled", returncode=0)
        # Mock rmtree to prevent errors in the 'finally' block
        mock_rmtree.return_value = None

        # Act
        # We run the command. os.path.exists is mocked to return True.
        result = runner.invoke(appint_app, ["static", "dummy.apk"])

        # Assert
        self.assertEqual(
            result.exit_code, 0, f"CLI command failed with output: {result.stdout}"
        )
        # Check that the file was checked
        mock_exists.assert_called_with("dummy.apk")
        mock_subprocess.assert_called_once()  # Check that apktool was called
        mock_save_print.assert_called_once()  # Check results were saved/printed
        mock_save_db.assert_called_once()   # Check DB save was called
        mock_rmtree.assert_called_once()      # Check cleanup was called

    @patch("chimera_intel.core.appint.logger")  # FIX: Patch the logger
    @patch("chimera_intel.core.appint.save_scan_to_db")
    @patch("chimera_intel.core.appint.save_or_print_results")
    @patch("chimera_intel.core.appint.os.path.exists", return_value=False)  # Mock os.path.exists
    @patch("chimera_intel.core.appint.console.print")
    def test_cli_static_analysis_file_not_found(
        self,
        mock_console_print,
        mock_exists,
        mock_save_print,
        mock_save_db,
        mock_logger,  # Argument for new logger mock
    ):
        """Tests the 'static' CLI command when the file is not found (mocks os.path.exists)."""
        # Arrange
        # os.path.exists is mocked via decorator to return False

        # Act
        result = runner.invoke(appint_app, ["static", "nonexistent.apk"])

        # Assert
        # The command should catch the error and exit with code 1
        self.assertEqual(
            result.exit_code, 1, f"CLI command failed with output: {result.stdout}"
        )
        mock_exists.assert_called_with("nonexistent.apk")

        # Check that the correct error message was printed
        mock_console_print.assert_called_with(
            "[red]Static analysis failed: APK file not found.[/red]"
        )
        # The other functions should not be called on failure
        mock_save_print.assert_not_called()
        mock_save_db.assert_not_called()


if __name__ == "__main__":
    unittest.main()