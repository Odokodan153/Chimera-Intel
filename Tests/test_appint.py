import unittest
from unittest.mock import patch, MagicMock, mock_open
from typer.testing import CliRunner
import subprocess  # Import subprocess to mock its exceptions
import os  # <-- FIX: Import os for path manipulation

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

    # --- Extended Test ---
    @patch("chimera_intel.core.appint.shutil.rmtree")
    @patch("chimera_intel.core.appint.subprocess.run")
    @patch("chimera_intel.core.appint.os.path.exists", return_value=True)
    @patch("chimera_intel.core.appint.os.walk")
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data='some_line_of_code\napi_key = "FAKE_API_KEY_1234567890"\n',
    )
    def test_analyze_apk_static_finds_secrets(
        self, mock_file, mock_os_walk, mock_exists, mock_subprocess, mock_rmtree
    ):
        """
        Tests that the static analysis function correctly finds a hardcoded secret.
        This covers the 'if match:' block inside the file read loop.
        """
        # Arrange
        # Mock subprocess.run to simulate successful decompilation
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # --- FIX: Make mock_os_walk return a realistic relative path ---
        # The function will call os.walk on "dummy.apk_decompiled"
        output_dir = "dummy.apk_decompiled"
        mock_subdir = "fake_dir"
        mock_filename = "strings.xml"
        # e.g., "dummy.apk_decompiled/fake_dir"
        mock_root_path = os.path.join(output_dir, mock_subdir) 
        
        # Mock os.walk to return one file to scan in a subdirectory
        mock_os_walk.return_value = [
            (mock_root_path, [], [mock_filename]),
        ]
        # ----------------------------------------------------------------

        # Act
        # This will create output_dir = "dummy.apk_decompiled"
        result = analyze_apk_static("dummy.apk") 

        # Assert
        self.assertIsNone(result.error)
        self.assertEqual(len(result.secrets_found), 1)
        self.assertEqual(result.secrets_found[0].secret_type, "api_key")
        self.assertEqual(result.secrets_found[0].line_number, 2)
        
        # --- FIX: Assert the correct *relative* path ---
        # The code calculates os.path.relpath("dummy.apk_decompiled/fake_dir/strings.xml", "dummy.apk_decompiled")
        # which should result in "fake_dir/strings.xml"
        # "fake_dir/strings.xml"
        expected_rel_path = os.path.join(mock_subdir, mock_filename) 
        self.assertEqual(result.secrets_found[0].file_path, expected_rel_path)
        # ------------------------------------------------
        
        mock_rmtree.assert_called_once()  # Ensure cleanup happens

    # --- Extended Test ---
    @patch("chimera_intel.core.appint.shutil.rmtree")
    @patch("chimera_intel.core.appint.subprocess.run")
    @patch("chimera_intel.core.appint.os.path.exists", return_value=True)
    def test_analyze_apk_static_apktool_not_found(
        self, mock_exists, mock_subprocess, mock_rmtree
    ):
        """
        Tests the 'except FileNotFoundError' block for when 'apktool' is not installed.
        """
        # Arrange
        mock_subprocess.side_effect = FileNotFoundError("apktool not found")

        # Act
        result = analyze_apk_static("dummy.apk")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("apktool not found. Please install it.", result.error)
        mock_rmtree.assert_called_once()  # Ensure cleanup happens

    # --- Extended Test ---
    @patch("chimera_intel.core.appint.shutil.rmtree")
    @patch("chimera_intel.core.appint.subprocess.run")
    @patch("chimera_intel.core.appint.os.path.exists", return_value=True)
    def test_analyze_apk_static_apktool_fails(
        self, mock_exists, mock_subprocess, mock_rmtree
    ):
        """
        Tests the 'except subprocess.CalledProcessError' block for when 'apktool' fails.
        """
        # Arrange
        mock_subprocess.side_effect = subprocess.CalledProcessError(
            1, "apktool", stderr="Decompilation failed"
        )

        # Act
        result = analyze_apk_static("dummy.apk")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("apktool failed: Decompilation failed", result.error)
        mock_rmtree.assert_called_once()  # Ensure cleanup happens

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.appint.logger")
    @patch("chimera_intel.core.appint.os.walk", return_value=[])
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
        mock_os_walk,
        mock_logger,
    ):
        """Tests a successful run of the 'static' CLI command by mocking dependencies."""
        # Arrange
        mock_subprocess.return_value = MagicMock(stdout="Decompiled", returncode=0)
        mock_rmtree.return_value = None

        # Act
        # FIX: Added 'static' command
        result = runner.invoke(appint_app, ["static", "dummy.apk"])

        # Assert
        self.assertEqual(
            result.exit_code, 0, f"CLI command failed with output: {result.stdout}"
        )
        mock_exists.assert_any_call("dummy.apk")
        mock_subprocess.assert_called_once()
        mock_save_print.assert_called_once()
        mock_save_db.assert_called_once()
        mock_rmtree.assert_called_once()

    # --- Extended Test ---
    @patch("chimera_intel.core.appint.logger")
    @patch("chimera_intel.core.appint.os.walk", return_value=[])
    @patch("chimera_intel.core.appint.save_scan_to_db")
    @patch("chimera_intel.core.appint.save_or_print_results")
    @patch("chimera_intel.core.appint.shutil.rmtree")
    @patch("chimera_intel.core.appint.subprocess.run")
    @patch("chimera_intel.core.appint.os.path.exists", return_value=True)
    @patch("chimera_intel.core.appint.console.print")
    def test_cli_static_analysis_with_output_file(
        self,
        mock_console_print,
        mock_exists,
        mock_subprocess,
        mock_rmtree,
        mock_save_print,
        mock_save_db,
        mock_os_walk,
        mock_logger,
    ):
        """
        Tests the CLI command when an '--output' file is specified.
        This covers the 'output_file' argument logic.
        """
        # Arrange
        mock_subprocess.return_value = MagicMock(stdout="Decompiled", returncode=0)

        # Act
        # FIX: Added 'static' command
        result = runner.invoke(appint_app, ["static", "dummy.apk", "--output", "test.json"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        # Check that save_or_print_results was called with the output file
        mock_save_print.assert_called_once()
        self.assertEqual(mock_save_print.call_args[0][1], "test.json")

    # --- Extended Test ---
    @patch("chimera_intel.core.appint.logger")
    @patch("chimera_intel.core.appint.save_scan_to_db")
    @patch("chimera_intel.core.appint.save_or_print_results")
    @patch("chimera_intel.core.appint.analyze_apk_static")
    @patch("chimera_intel.core.appint.console.print")
    def test_cli_static_analysis_unexpected_error(
        self,
        mock_console_print,
        mock_analyze,
        mock_save_print,
        mock_save_db,
        mock_logger,
    ):
        """
        Tests the final 'except Exception' block in the CLI command.
        """
        # Arrange
        # Mock the analysis to return a successful result
        mock_analyze.return_value = MagicMock(error=None, model_dump=MagicMock(return_value={}))
        # Mock the save_scan_to_db to raise a generic error
        mock_save_db.side_effect = Exception("Database connection failed")

        # Act
        # FIX: Added 'static' command
        result = runner.invoke(appint_app, ["static", "dummy.apk"])

        # Assert
        self.assertEqual(result.exit_code, 1)
        mock_console_print.assert_called_with(
            "[red]An unexpected error occurred: Database connection failed[/red]"
        )

    @patch("chimera_intel.core.appint.logger")
    @patch("chimera_intel.core.appint.save_scan_to_db")
    @patch("chimera_intel.core.appint.save_or_print_results")
    @patch("chimera_intel.core.appint.os.path.exists", return_value=False)
    @patch("chimera_intel.core.appint.console.print")
    def test_cli_static_analysis_file_not_found(
        self,
        mock_console_print,
        mock_exists,
        mock_save_print,
        mock_save_db,
        mock_logger,
    ):
        """Tests the 'static' CLI command when the file is not found (mocks os.path.exists)."""
        # Act
        # FIX: Added 'static' command
        result = runner.invoke(appint_app, ["static", "nonexistent.apk"])

        # Assert
        self.assertEqual(result.exit_code, 1)
        mock_exists.assert_called_with("nonexistent.apk")
        mock_console_print.assert_called_with(
            "[red]Static analysis failed: APK file not found.[/red]"
        )
        mock_save_print.assert_not_called()
        mock_save_db.assert_not_called()


if __name__ == "__main__":
    unittest.main()