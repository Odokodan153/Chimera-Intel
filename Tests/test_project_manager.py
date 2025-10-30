import unittest
import os
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
import typer

from chimera_intel.core.project_manager import (
    create_project,
    get_active_project,
    list_projects,
    set_project_context,
    resolve_target,
    project_app,
    CONTEXT_FILE,
    get_project_config_by_name,
)
from chimera_intel.core.schemas import ProjectConfig, User

runner = CliRunner()


class TestProjectManager(unittest.TestCase):
    """Test cases for the project_manager module."""

    def setUp(self):
        """Clean up context file before each test."""
        if os.path.exists(CONTEXT_FILE):
            os.remove(CONTEXT_FILE)

    def tearDown(self):
        """Clean up context file after each test."""
        if os.path.exists(CONTEXT_FILE):
            os.remove(CONTEXT_FILE)

    @patch("chimera_intel.core.project_manager.get_active_user")
    @patch("chimera_intel.core.project_manager.get_db_connection")
    def test_create_project_success(self, mock_get_conn, mock_get_user):
        """Tests the successful creation of a new project."""
        mock_get_user.return_value = User(
            id=1,
            username="testadmin",
            hashed_password="",
            email="testadmin@example.com",
        )
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = [1]  # Project ID

        success = create_project("Test Project", "example.com", "Test Company", "TCKR")
        self.assertTrue(success)

    @patch("chimera_intel.core.project_manager.get_active_user")
    @patch("chimera_intel.core.project_manager.get_db_connection")
    def test_list_projects(self, mock_get_conn, mock_get_user):
        """Tests listing projects for a user."""
        mock_get_user.return_value = User(
            id=1, username="testuser", hashed_password="", email="testuser@example.com"
        )
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [("Project1",), ("Project2",)]

        projects = list_projects()
        self.assertEqual(len(projects), 2)
        self.assertIn("Project1", projects)

    @patch("chimera_intel.core.project_manager.get_project_config_by_name")
    def test_get_active_project(self, mock_get_config):
        """Tests retrieving the active project."""
        set_project_context("active_project")
        mock_get_config.return_value = ProjectConfig(
            project_name="active_project", created_at="", domain="active.com"
        )

        project = get_active_project()
        self.assertIsNotNone(project)
        self.assertEqual(project.project_name, "active_project")

    def test_resolve_target_with_target(self):
        """Tests that resolve_target returns the provided target."""
        target = "explicit-target.com"
        resolved = resolve_target(target, ["domain"])
        self.assertEqual(resolved, target)

    @patch("chimera_intel.core.project_manager.get_active_project")
    def test_resolve_target_with_project(self, mock_get_active_project):
        """Tests that resolve_target falls back to the active project."""
        mock_get_active_project.return_value = ProjectConfig(
            project_name="TestProject", created_at="", domain="project-domain.com"
        )
        resolved = resolve_target(None, ["domain"])
        self.assertEqual(resolved, "project-domain.com")

    @patch("chimera_intel.core.project_manager.get_active_project", return_value=None)
    def test_resolve_target_no_target_no_project(self, mock_get_active_project):
        """Tests that resolve_target exits if no target can be found."""
        with self.assertRaises(typer.Exit):
            resolve_target(None, ["domain"])

    @patch("chimera_intel.core.project_manager.create_project")
    @patch("chimera_intel.core.project_manager.set_project_context")
    def test_cli_init_project(self, mock_set_context, mock_create_project):
        """Tests the 'project init' CLI command."""
        mock_create_project.return_value = True
        result = runner.invoke(
            project_app, ["init", "NewProject", "--domain", "new.com"]
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("created successfully", result.stdout)
        mock_create_project.assert_called_with("NewProject", "new.com", None, None)
        mock_set_context.assert_called_with("NewProject")

    @patch("chimera_intel.core.project_manager.set_project_context")
    def test_cli_use_project(self, mock_set_context):
        """Tests the 'project use' CLI command."""
        mock_set_context.return_value = True
        result = runner.invoke(project_app, ["use", "MyProject"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Active project is now 'MyProject'", result.stdout)
        mock_set_context.assert_called_with("MyProject")

    @patch("chimera_intel.core.project_manager.get_active_project")
    def test_cli_status_command(self, mock_get_active_project):
        """Tests the 'project status' CLI command."""
        mock_get_active_project.return_value = ProjectConfig(
            project_name="StatusProject",
            created_at="",
            domain="status.com",
            company_name="Status Inc.",
            ticker="STT",
        )
        result = runner.invoke(project_app, ["status"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Active project: StatusProject", result.stdout)
        self.assertIn("Domain: status.com", result.stdout)
        self.assertIn("Company Name: Status Inc.", result.stdout)
        self.assertIn("Ticker: STT", result.stdout)

    @patch("chimera_intel.core.project_manager.add_user_to_project")
    def test_cli_share_project(self, mock_add_user_to_project):
        """Tests the 'project share' CLI command."""
        mock_add_user_to_project.return_value = True
        result = runner.invoke(
            project_app,
            ["share", "ShareProject", "--user", "collaborator", "--role", "analyst"],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Successfully shared", result.stdout)
        mock_add_user_to_project.assert_called_with(
            "ShareProject", "collaborator", "analyst"
        )

    @patch("chimera_intel.core.project_manager.get_db_connection")
    def test_get_project_config_by_name(self, mock_get_conn):
        """Tests retrieving a project config from the database."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = (
            '{"project_name": "DBProject", "domain": "db.com", "created_at": ""}',
        )

        project_config = get_project_config_by_name("DBProject")
        self.assertIsNotNone(project_config)
        self.assertEqual(project_config.project_name, "DBProject")


if __name__ == "__main__":
    unittest.main()
