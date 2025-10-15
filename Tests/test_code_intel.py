import unittest
from unittest.mock import patch, MagicMock
import git
import json
from typer.testing import CliRunner

from chimera_intel.core.code_intel import analyze_git_repository, code_intel_app
from chimera_intel.core.schemas import RepoAnalysisResult, CommitterInfo

runner = CliRunner()


class TestCodeIntel(unittest.TestCase):
    """Test cases for the code_intel module."""

    @patch("chimera_intel.core.code_intel.shutil.rmtree")
    @patch("chimera_intel.core.code_intel.git.Repo.clone_from")
    def test_analyze_git_repository_success(self, mock_clone_from, mock_rmtree):
        """Tests a successful repository analysis by mocking the git clone."""
        # Arrange

        mock_repo = MagicMock()
        mock_author1 = MagicMock()
        mock_author1.name = "Jane Doe"
        mock_author1.email = "jane@example.com"
        mock_commit1 = MagicMock(
            author=mock_author1, message="feat: Add new dashboard feature"
        )
        mock_author2 = MagicMock()
        mock_author2.name = "John Smith"
        mock_author2.email = "john@example.com"
        mock_commit2 = MagicMock(
            author=mock_author2, message="fix: Correct bug in API endpoint"
        )
        mock_repo.iter_commits.return_value = [mock_commit1, mock_commit2]
        mock_clone_from.return_value = mock_repo

        # Act

        result = analyze_git_repository("https://github.com/user/repo.git")

        # Assert

        self.assertIsInstance(result, RepoAnalysisResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_commits, 2)
        self.assertEqual(result.total_committers, 2)
        self.assertEqual(len(result.top_committers), 2)
        self.assertIn("feature", result.commit_keywords)
        self.assertIn("bug", result.commit_keywords)
        self.assertEqual(result.commit_keywords["feature"], 1)
        mock_rmtree.assert_called_once()  # Verify cleanup was called

    @patch("chimera_intel.core.code_intel.shutil.rmtree")
    @patch("chimera_intel.core.code_intel.git.Repo.clone_from")
    def test_analyze_git_repository_git_command_error(
        self, mock_clone_from, mock_rmtree
    ):
        """Tests the function's error handling when a GitCommandError occurs."""
        # Arrange: Simulate a git command failure (e.g., repo not found)

        mock_clone_from.side_effect = git.GitCommandError(
            "clone", "Repository not found"
        )

        # Act

        result = analyze_git_repository("https://github.com/user/nonexistent-repo.git")

        # Assert

        self.assertIsInstance(result, RepoAnalysisResult)
        self.assertIsNotNone(result.error)
        self.assertIn("Git command failed", result.error)
        self.assertEqual(result.total_commits, 0)
        mock_rmtree.assert_called_once()  # Ensure cleanup is still called

    @patch("chimera_intel.core.code_intel.shutil.rmtree")
    @patch("chimera_intel.core.code_intel.git.Repo.clone_from")
    def test_analyze_git_repository_unexpected_exception(
        self, mock_clone_from, mock_rmtree
    ):
        """Tests the function's general exception handling."""
        # Arrange: Simulate an unexpected error

        mock_clone_from.side_effect = Exception("An unexpected network error")

        # Act

        result = analyze_git_repository("https://github.com/user/repo.git")

        # Assert

        self.assertIsInstance(result, RepoAnalysisResult)
        self.assertIsNotNone(result.error)
        self.assertIn("An unexpected error occurred", result.error)
        self.assertEqual(result.total_committers, 0)
        mock_rmtree.assert_called_once()

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.code_intel.save_scan_to_db")
    @patch("chimera_intel.core.code_intel.analyze_git_repository")
    def test_cli_repo_analysis_success(self, mock_analyze_repo, mock_save_db):
        """Tests a successful run of the 'repo' CLI command."""
        # Arrange

        mock_analyze_repo.return_value = RepoAnalysisResult(
            repository_url="https://github.com/user/repo.git",
            total_commits=10,
            total_committers=3,
            top_committers=[
                CommitterInfo(name="Test User", email="test@user.com", commit_count=5)
            ],
            commit_keywords={"feat": 5},
        )

        # Act

        result = runner.invoke(
            code_intel_app, ["repo", "https://github.com/user/repo.git"]
        )

        # Assert

        self.assertEqual(result.exit_code, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["repository_url"], "https://github.com/user/repo.git")
        self.assertEqual(output["total_commits"], 10)
        mock_analyze_repo.assert_called_with("https://github.com/user/repo.git")
        mock_save_db.assert_called_once()

    def test_cli_repo_no_url_fails(self):
        """
        Tests that the CLI command fails correctly if no repository URL is provided.
        """
        # Act

        result = runner.invoke(code_intel_app, ["repo"])

        # Assert
        # Typer exits with code 2 for missing arguments

        self.assertEqual(result.exit_code, 2)
        self.assertIn("Missing argument 'REPO_URL'", result.stdout)


if __name__ == "__main__":
    unittest.main()
