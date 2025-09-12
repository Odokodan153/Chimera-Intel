import unittest
from unittest.mock import patch, MagicMock, mock_open

from chimera_intel.core.daemon import (
    start_daemon,
    stop_daemon,
    _get_daemon_status,
    _run_workflow,
)
from chimera_intel.core.schemas import ProjectConfig, DaemonConfig


class TestDaemon(unittest.TestCase):
    """Test cases for the Daemon module."""

    @patch("chimera_intel.core.daemon.os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data="12345")
    @patch("chimera_intel.core.daemon.os.kill")
    def test_get_daemon_status_running(self, mock_kill, mock_file, mock_exists):
        """Tests the status check when the daemon is running."""
        pid = _get_daemon_status()
        self.assertEqual(pid, 12345)
        mock_kill.assert_called_with(
            12345, 0
        )  # os.kill(pid, 0) checks if process exists

    @patch("chimera_intel.core.daemon.os.path.exists", return_value=False)
    def test_get_daemon_status_not_running(self, mock_exists):
        """Tests the status check when the PID file does not exist."""
        pid = _get_daemon_status()
        self.assertIsNone(pid)

    @patch("chimera_intel.core.daemon.subprocess.run")
    def test_run_workflow(self, mock_subprocess_run):
        """Tests that the workflow runner calls the correct commands."""
        workflow = ["scan footprint {target}", "analysis diff run footprint {target}"]
        _run_workflow(workflow, "example.com")
        self.assertEqual(mock_subprocess_run.call_count, 2)
        first_call_args = mock_subprocess_run.call_args_list[0].args[0]
        self.assertIn("chimera scan footprint example.com", first_call_args)

    @patch("chimera_intel.core.daemon._get_daemon_status", return_value=None)
    @patch("chimera_intel.core.daemon.get_active_project")
    @patch("chimera_intel.core.daemon.os.fork")
    @patch("chimera_intel.core.daemon.sys.exit")
    def test_start_daemon_no_project(
        self, mock_exit, mock_fork, mock_get_project, mock_status
    ):
        """Tests that the daemon fails to start without a configured project."""
        mock_get_project.return_value = None
        start_daemon()
        mock_exit.assert_called_with(1)


if __name__ == "__main__":
    unittest.main()
