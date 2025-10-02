import unittest
import os
import signal
import subprocess
from unittest.mock import patch, call
from typer.testing import CliRunner

from chimera_intel.core.daemon import (
    _get_daemon_status,
    _run_workflow,
    daemon_app,
    PID_FILE,
    start_daemon,
)
from chimera_intel.core.schemas import ProjectConfig, DaemonConfig, ScheduledWorkflow

runner = CliRunner()


class TestDaemon(unittest.TestCase):
    """Test cases for the daemon module."""

    def setUp(self):
        """Clean up PID file before each test."""
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)

    def tearDown(self):
        """Clean up PID file after each test."""
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)

    @patch("chimera_intel.core.daemon.os.kill")
    def test_get_daemon_status_running(self, mock_os_kill):
        """Tests the status check when the daemon is running."""
        with open(PID_FILE, "w") as f:
            f.write("12345")
        pid = _get_daemon_status()

        self.assertEqual(pid, 12345)
        mock_os_kill.assert_called_with(12345, 0)

    def test_get_daemon_status_not_running(self):
        """Tests the status check when the daemon is not running."""
        pid = _get_daemon_status()
        self.assertIsNone(pid)

    @patch("chimera_intel.core.daemon.subprocess.run")
    def test_run_workflow(self, mock_subprocess_run):
        """Tests that the workflow runner calls commands correctly."""
        workflow_steps = ["scan footprint {target}", "scan web {target}"]
        _run_workflow(workflow_steps, "example.com")

        self.assertEqual(mock_subprocess_run.call_count, 2)
        mock_subprocess_run.assert_has_calls(
            [
                call(
                    "chimera scan footprint example.com",
                    shell=True,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ),
                call(
                    "chimera scan web example.com",
                    shell=True,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ),
            ]
        )

    @patch(
        "chimera_intel.core.daemon.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "cmd"),
    )
    def test_run_workflow_step_fails(self, mock_subprocess_run):
        """Tests that the workflow continues even if a step fails."""
        workflow_steps = ["scan footprint {target}", "scan web {target}"]
        _run_workflow(workflow_steps, "example.com")
        self.assertEqual(mock_subprocess_run.call_count, 2)

    @patch("chimera_intel.core.daemon._get_daemon_status", return_value=None)
    @patch("chimera_intel.core.daemon.get_active_project")
    def test_start_daemon_no_project(self, mock_get_project, mock_status):
        """Tests that the daemon fails to start if no active project is configured."""
        mock_get_project.return_value = None

        result = runner.invoke(daemon_app, ["start"])
        self.assertEqual(result.exit_code, 1)

    @patch("chimera_intel.core.daemon._get_daemon_status", return_value=None)
    @patch("chimera_intel.core.daemon.get_active_project")
    def test_start_daemon_no_daemon_config(self, mock_get_project, mock_status):
        """Tests that the daemon fails to start if the project has no daemon config."""
        mock_get_project.return_value = ProjectConfig(
            project_name="Test", created_at="", domain="test.com"
        )
        result = runner.invoke(daemon_app, ["start"])
        self.assertEqual(result.exit_code, 1)

    @patch("chimera_intel.core.daemon.os.fork", side_effect=OSError)
    @patch("chimera_intel.core.daemon._get_daemon_status", return_value=None)
    @patch("chimera_intel.core.daemon.get_active_project")
    def test_start_daemon_fork_fails(self, mock_get_project, mock_status, mock_fork):
        """Tests that the daemon start fails if os.fork raises an OSError."""
        mock_get_project.return_value = ProjectConfig(
            project_name="Test",
            created_at="",
            domain="test.com",
            daemon_config=DaemonConfig(
                enabled=True,
                workflows=[
                    ScheduledWorkflow(name="test", schedule="* * * * *", steps=[])
                ],
            ),
        )
        with self.assertRaises(SystemExit):
            start_daemon()

    @patch("chimera_intel.core.daemon._get_daemon_status")
    def test_stop_daemon_not_running(self, mock_status):
        """Tests stopping the daemon when it's not running."""
        mock_status.return_value = None
        result = runner.invoke(daemon_app, ["stop"])
        self.assertIn("Daemon is not running", result.stdout)

    @patch("chimera_intel.core.daemon._get_daemon_status")
    @patch("chimera_intel.core.daemon.os.kill")
    def test_stop_daemon_success(self, mock_os_kill, mock_status):
        """Tests successfully stopping a running daemon."""
        mock_status.return_value = 12345
        result = runner.invoke(daemon_app, ["stop"])
        self.assertIn("stopped successfully", result.stdout)
        mock_os_kill.assert_called_with(12345, signal.SIGTERM)

    @patch("chimera_intel.core.daemon._get_daemon_status")
    @patch("chimera_intel.core.daemon.os.kill", side_effect=OSError)
    def test_stop_daemon_kill_fails(self, mock_os_kill, mock_status):
        """Tests stopping the daemon when os.kill fails."""
        mock_status.return_value = 12345
        result = runner.invoke(daemon_app, ["stop"])
        self.assertIn("Could not stop the daemon process", result.stdout)

    @patch("chimera_intel.core.daemon._get_daemon_status")
    def test_status_daemon_command(self, mock_status):
        """Tests the daemon status command."""
        mock_status.return_value = 12345
        with patch("chimera_intel.core.daemon.get_active_project") as mock_get_project:
            mock_get_project.return_value = ProjectConfig(
                project_name="TestProject", created_at="", domain="example.com"
            )
            result = runner.invoke(daemon_app, ["status"])
            self.assertIn("Daemon is running", result.stdout)
