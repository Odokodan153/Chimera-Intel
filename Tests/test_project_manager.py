import unittest
import os
import yaml
from unittest.mock import patch, mock_open
from typer.testing import CliRunner
import typer

from chimera_intel.cli import app
from chimera_intel.core.project_manager import (
    create_project,
    set_project_context,
    get_active_project,
    resolve_target,
    list_projects,  # New import
    get_project_config_by_name,  # New import
    PROJECTS_DIR,
    CONTEXT_FILE,
)
from chimera_intel.core.schemas import ProjectConfig

runner = CliRunner()


class TestProjectManager(unittest.TestCase):
    """Test cases for the Intelligence Project Manager module."""

    def setUp(self):
        """Clean up any context files or mock directories before each test."""
        if os.path.exists(CONTEXT_FILE):
            os.remove(CONTEXT_FILE)

    def tearDown(self):
        """Clean up any context files after each test."""
        if os.path.exists(CONTEXT_FILE):
            os.remove(CONTEXT_FILE)

    @patch("chimera_intel.core.project_manager.os.path.exists")
    @patch("chimera_intel.core.project_manager.os.makedirs")
    @patch("builtins.open", new_callable=mock_open)
    def test_create_project_success(self, mock_file, mock_makedirs, mock_exists):
        """Tests the successful creation of a new project."""
        mock_exists.return_value = False
        success = create_project(
            project_name="test_project",
            domain="example.com",
            company_name="Test Corp",
            ticker="TEST",
        )
        self.assertTrue(success)
        mock_makedirs.assert_called_with(os.path.join(PROJECTS_DIR, "test_project"))
        mock_file.assert_called_with(
            os.path.join(PROJECTS_DIR, "test_project", "project.yaml"), "w"
        )
        with patch("yaml.dump") as mock_yaml_dump:
            create_project("test_project_2", "example.com", None, None)
            self.assertTrue(mock_yaml_dump.called)

    @patch("chimera_intel.core.project_manager.os.path.exists", return_value=True)
    def test_create_project_already_exists(self, mock_exists):
        """Tests that creating a project that already exists fails gracefully."""
        success = create_project("existing_project", "example.com", None, None)
        self.assertFalse(success)

    @patch("chimera_intel.core.project_manager.os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open)
    def test_set_and_get_project_context(self, mock_file, mock_exists):
        """Tests setting and retrieving the active project context."""
        success = set_project_context("test_project")
        self.assertTrue(success)
        mock_file.assert_called_with(CONTEXT_FILE, "w")
        mock_file().write.assert_called_with("test_project")

        mock_yaml_data = yaml.dump(
            {
                "project_name": "test_project",
                "created_at": "2025-01-01",
                "domain": "example.com",
            }
        )
        m = mock_open()
        m.side_effect = (
            mock_open(read_data="test_project").return_value,
            mock_open(read_data=mock_yaml_data).return_value,
        )
        with patch("builtins.open", m):
            with patch("chimera_intel.core.project_manager.get_project_config_by_name") as mock_get_config:
                mock_get_config.return_value = ProjectConfig(project_name="test_project", created_at="2025-01-01", domain="example.com")
                active_project = get_active_project()
                mock_get_config.assert_called_with("test_project")
                self.assertIsNotNone(active_project)
                self.assertEqual(active_project.project_name, "test_project")

    def test_get_active_project_no_context_file(self):
        """Tests that getting the active project returns None if no context is set."""
        active_project = get_active_project()
        self.assertIsNone(active_project)

    # --- NEW TEST CASES ---
    @patch("chimera_intel.core.project_manager.os.path.isdir")
    @patch("chimera_intel.core.project_manager.os.listdir")
    def test_list_projects(self, mock_listdir, mock_isdir):
        """Tests the function that lists all project directories."""
        # Simulate a directory with two projects and one file
        mock_listdir.return_value = ["project_a", "project_b", "a_file.txt"]
        # os.path.isdir will be called for each item, return True for dirs
        mock_isdir.side_effect = lambda path: "project" in path

        projects = list_projects()
        self.assertEqual(len(projects), 2)
        self.assertIn("project_a", projects)
        self.assertIn("project_b", projects)
        self.assertNotIn("a_file.txt", projects)

    @patch("chimera_intel.core.project_manager.os.path.exists", return_value=True)
    @patch("builtins.open")
    @patch("yaml.safe_load")
    def test_get_project_config_by_name_success(self, mock_safe_load, mock_open, mock_exists):
        """Tests loading a project config successfully."""
        mock_config_data = {"project_name": "my_project", "created_at": "now", "domain": "my.com"}
        mock_safe_load.return_value = mock_config_data
        
        config = get_project_config_by_name("my_project")

        self.assertIsInstance(config, ProjectConfig)
        self.assertEqual(config.project_name, "my_project")
        mock_open.assert_called_with(os.path.join(PROJECTS_DIR, "my_project", "project.yaml"), "r")

    @patch("chimera_intel.core.project_manager.os.path.exists", return_value=False)
    def test_get_project_config_by_name_not_found(self, mock_exists):
        """Tests loading a non-existent project config."""
        config = get_project_config_by_name("non_existent_project")
        self.assertIsNone(config)

    # --- CLI Command Tests ---
    @patch("chimera_intel.core.project_manager.create_project", return_value=True)
    @patch("chimera_intel.core.project_manager.set_project_context")
    def test_cli_project_init_command(self, mock_set_context, mock_create):
        """Tests the 'project init' CLI command."""
        result = runner.invoke(
            app,
            [
                "project",
                "init",
                "new_cli_project",
                "--domain",
                "cli.com",
                "--company",
                "CLI Corp",
            ],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Project 'new_cli_project' created", result.stdout)
        mock_create.assert_called_with("new_cli_project", "cli.com", "CLI Corp", None)
        mock_set_context.assert_called_with("new_cli_project")

    @patch("chimera_intel.core.project_manager.set_project_context", return_value=True)
    def test_cli_project_use_command(self, mock_set_context):
        """Tests the 'project use' CLI command."""
        result = runner.invoke(app, ["project", "use", "existing_project"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Active project is now 'existing_project'", result.stdout)
        mock_set_context.assert_called_with("existing_project")


class TestResolveTarget(unittest.TestCase):
    """Test cases specifically for the resolve_target function."""

    def test_resolve_target_with_direct_argument(self):
        """Tests that a directly provided target is always returned."""
        result = resolve_target("explicit.com", required_assets=["domain"])
        self.assertEqual(result, "explicit.com")

    @patch("chimera_intel.core.project_manager.get_active_project")
    def test_resolve_target_from_project_domain(self, mock_get_project):
        """Tests successfully resolving a target from the active project's domain."""
        mock_project = ProjectConfig(
            project_name="Test", created_at="", domain="project.com"
        )
        mock_get_project.return_value = mock_project
        result = resolve_target(None, required_assets=["domain"])
        self.assertEqual(result, "project.com")

    @patch("chimera_intel.core.project_manager.get_active_project")
    def test_resolve_target_from_project_company_name(self, mock_get_project):
        """Tests successfully resolving a target from the active project's company_name."""
        mock_project = ProjectConfig(
            project_name="Test", created_at="", company_name="Project Corp"
        )
        mock_get_project.return_value = mock_project
        result = resolve_target(None, required_assets=["company_name"])
        self.assertEqual(result, "Project Corp")

    @patch("chimera_intel.core.project_manager.get_active_project")
    def test_resolve_target_no_arg_no_project(self, mock_get_project):
        """Tests that it exits if no target is given and no project is active."""
        mock_get_project.return_value = None
        with self.assertRaises(typer.Exit):
            resolve_target(None, required_assets=["domain"])

    @patch("chimera_intel.core.project_manager.get_active_project")
    def test_resolve_target_project_missing_asset(self, mock_get_project):
        """Tests that it exits if the active project doesn't have the required asset."""
        mock_project = ProjectConfig(
            project_name="Test", created_at="", domain="project.com"
        )
        mock_get_project.return_value = mock_project
        with self.assertRaises(typer.Exit):
            resolve_target(None, required_assets=["company_name"])


if __name__ == "__main__":
    unittest.main()