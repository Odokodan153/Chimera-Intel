import unittest
import os
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from chimera_intel.cli import app
from chimera_intel.core.project_manager import (
    create_project,
    get_active_project,
    list_projects,
    CONTEXT_FILE
)
from chimera_intel.core.schemas import ProjectConfig, User

runner = CliRunner()


class TestProjectManager(unittest.TestCase):
    """Test cases for the database-driven Intelligence Project Manager module."""

    def setUp(self):
        """Clean up any context files before each test."""
        if os.path.exists(CONTEXT_FILE):
            os.remove(CONTEXT_FILE)

    def tearDown(self):
        """Clean up any context files after each test."""
        if os.path.exists(CONTEXT_FILE):
            os.remove(CONTEXT_FILE)

    @patch("chimera_intel.core.project_manager.get_active_user")
    @patch("chimera_intel.core.project_manager.get_db_connection")
    def test_create_project_success(self, mock_get_conn, mock_get_user):
        """Tests the successful creation of a new project in the database."""
        # Arrange

        mock_get_user.return_value = User(
            id=1, username="testadmin", hashed_password=""
        )
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = [1]  # Simulate RETURNING id

        # Act

        success = create_project(
            project_name="db_project",
            domain="db-example.com",
            company_name="DB Corp",
            ticker="DBT",
        )

        # Assert

        self.assertTrue(success)
        # Check that project was inserted

        self.assertIn(
            "INSERT INTO projects", mock_cursor.execute.call_args_list[0][0][0]
        )
        # Check that user was assigned as admin

        self.assertIn(
            "INSERT INTO project_users", mock_cursor.execute.call_args_list[1][0][0]
        )
        self.assertEqual(mock_cursor.execute.call_args_list[1][0][1], (1, 1, "admin"))
        mock_conn.commit.assert_called_once()

    @patch("chimera_intel.core.project_manager.get_active_user")
    @patch("chimera_intel.core.project_manager.get_db_connection")
    def test_list_projects(self, mock_get_conn, mock_get_user):
        """Tests listing projects a user has access to."""
        mock_get_user.return_value = User(id=1, username="testuser", hashed_password="")
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [("Project A",), ("Project B",)]

        projects = list_projects()
        self.assertEqual(len(projects), 2)
        self.assertIn("Project A", projects)
        mock_cursor.execute.assert_called_once()

    @patch("chimera_intel.core.project_manager.get_project_config_by_name")
    def test_get_active_project(self, mock_get_config):
        """Tests retrieving the active project context and fetching its config from DB."""
        # Set a context locally

        with open(CONTEXT_FILE, "w") as f:
            f.write("active_proj")
        mock_get_config.return_value = ProjectConfig(
            project_name="active_proj", created_at="", domain="active.com"
        )

        project = get_active_project()

        self.assertIsNotNone(project)
        self.assertEqual(project.project_name, "active_proj")
        mock_get_config.assert_called_once_with("active_proj")

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.project_manager.create_project", return_value=True)
    @patch("chimera_intel.core.project_manager.set_project_context")
    def test_cli_project_init_command(self, mock_set_context, mock_create):
        """Tests the 'project init' CLI command with the new DB backend."""
        result = runner.invoke(
            app,
            [
                "project",
                "init",
                "new_cli_project",
                "--domain",
                "cli.com",
            ],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Project 'new_cli_project' created", result.stdout)
        mock_create.assert_called_with("new_cli_project", "cli.com", None, None)
        mock_set_context.assert_called_with("new_cli_project")

    @patch("chimera_intel.core.project_manager.add_user_to_project", return_value=True)
    def test_cli_project_share_command(self, mock_add_user):
        """Tests the new 'project share' CLI command."""
        result = runner.invoke(
            app,
            [
                "project",
                "share",
                "my_project",
                "--user",
                "teammate",
                "--role",
                "analyst",
            ],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Successfully shared 'my_project' with 'teammate'", result.stdout)
        mock_add_user.assert_called_once_with("my_project", "teammate", "analyst")
