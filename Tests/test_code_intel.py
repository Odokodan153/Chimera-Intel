import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from httpx import Response, HTTPStatusError, Request

from chimera_intel.core.code_intel import (
    search_github_leaks,
    search_gitlab_leaks,
    analyze_git_repository,
    code_intel_app
)
from chimera_intel.core.schemas import (
    GitHubLeaksResult, 
    GitLabLeaksResult,
    RepoAnalysisResult
)
import git
runner = CliRunner()

class TestCodeIntel(unittest.TestCase):
    """Test cases for the combined Code Intelligence (CODEINT) module."""

    # --- Test API Leak Search ---

    @patch("chimera_intel.core.code_intel.sync_client.get")
    @patch("chimera_intel.core.code_intel.API_KEYS")
    def test_search_github_leaks_success(self, mock_api_keys, mock_get):
        """Tests a successful GitHub code search with the correct schema."""
        # Arrange
        mock_api_keys.github_pat = "fake_gh_pat"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        # Mock the new, correct API response structure
        mock_response.json.return_value = {
            "total_count": 1,
            "items": [
                {
                    "html_url": "https://github.com/test-org/test-repo/blob/main/config.yml",
                    "repository": {
                        "full_name": "test-org/test-repo",
                        "html_url": "https://github.com/test-org/test-repo",
                        "private": False
                    }
                }
            ],
        }
        mock_get.return_value = mock_response
        
        # Act
        result = search_github_leaks(keywords=["api_key"], org_name="test-org")

        # Assert
        self.assertIsInstance(result, GitHubLeaksResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_count, 1)
        self.assertEqual(result.items[0].repository.full_name, "test-org/test-repo")
        self.assertEqual(result.items[0].repository.html_url, "https://github.com/test-org/test-repo")
        self.assertEqual(result.items[0].html_url, "https://github.com/test-org/test-repo/blob/main/config.yml")
        mock_get.assert_called_with(
            unittest.mock.ANY,
            headers=unittest.mock.ANY,
            params={"q": '"api_key" org:test-org', "per_page": 50}
        )

    @patch("chimera_intel.core.code_intel.sync_client.get")
    @patch("chimera_intel.core.code_intel.API_KEYS")
    def test_search_github_rate_limit(self, mock_api_keys, mock_get):
        """Tests rate limit handling for GitHub (Point 2)."""
        # Arrange
        mock_api_keys.github_pat = "fake_gh_pat"
        mock_request = MagicMock(spec=Request)
        mock_response = MagicMock(spec=Response, status_code=403)
        mock_get.side_effect = HTTPStatusError(
            "Rate Limit", request=mock_request, response=mock_response
        )

        # Act
        result = search_github_leaks(keywords=["api_key"])

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("GitHub API rate limit exceeded", result.error)

    @patch("chimera_intel.core.code_intel.API_KEYS")
    def test_search_gitlab_no_key(self, mock_api_keys):
        """Tests GitLab search with no API key."""
        mock_api_keys.gitlab_pat = None
        result = search_gitlab_leaks(keywords=["api_key"])
        self.assertIsNotNone(result.error)
        self.assertIn("GITLAB_PAT not found", result.error)

    # --- Test Repo Analysis ---

    @patch("chimera_intel.core.code_intel.git.Repo.clone_from")
    @patch("chimera_intel.core.code_intel.shutil.rmtree")
    def test_analyze_git_repository_success(self, mock_rmtree, mock_clone_from):
        """Tests a successful repository analysis."""
        # Arrange
        mock_repo = MagicMock()
        mock_author = MagicMock(name="Test User", email="test@example.com")
        mock_commit = MagicMock(author=mock_author, message="feat: new feature")
        mock_repo.iter_commits.return_value = [mock_commit]
        mock_clone_from.return_value = mock_repo
        
        # Act
        result = analyze_git_repository("http://test.repo")
        
        # Assert
        self.assertIsInstance(result, RepoAnalysisResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_commits, 1)
        self.assertEqual(result.total_committers, 1)
        self.assertEqual(result.top_committers[0].name, "Test User")
        self.assertEqual(result.commit_keywords["feature"], 1)
        mock_rmtree.assert_called() # Ensure cleanup

    @patch("chimera_intel.core.code_intel.git.Repo.clone_from")
    @patch("chimera_intel.core.code_intel.shutil.rmtree")
    def test_analyze_git_repository_clone_fail(self, mock_rmtree, mock_clone_from):
        """Tests graceful handling of a failed clone (Point 3)."""
        # Arrange
        mock_clone_from.side_effect = git.GitCommandError("clone", "failed")
        
        # Act
        result = analyze_git_repository("http://private.repo")
        
        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("Git command failed", result.error)
        self.assertIn("private or deleted", result.error)
        mock_rmtree.assert_called() # Ensure cleanup still happens

    # --- Test New Parallel Command ---

    @patch("chimera_intel.core.code_intel.save_scan_to_db")
    @patch("chimera_intel.core.code_intel.analyze_git_repository")
    @patch("chimera_intel.core.code_intel.search_gitlab_leaks")
    @patch("chimera_intel.core.code_intel.search_github_leaks")
    @patch("chimera_intel.core.code_intel.save_or_print_results")
    def test_cli_analyze_repo_leaks(
        self, mock_save_print, mock_gh_search, mock_gl_search, 
        mock_analyze_repo, mock_save_db
    ):
        """Tests the new 'analyze-repo-leaks' command (Points 1, 4, 5, 6)."""
        # Arrange
        
        # 1. Mock GitHub Search (Point 1 & 6)
        mock_gh_repo_public = MagicMock(
            full_name="org/public-repo", 
            html_url="https://github.com/org/public-repo", 
            private=False
        )
        mock_gh_repo_private = MagicMock(
            full_name="org/private-repo", 
            html_url="https://github.com/org/private-repo", 
            private=True
        )
        mock_gh_search.return_value = GitHubLeaksResult(
            total_count=2,
            items=[
                MagicMock(repository=mock_gh_repo_public),
                MagicMock(repository=mock_gh_repo_private) # This one should be skipped
            ]
        )
        
        # 2. Mock GitLab Search (Point 1)
        mock_gl_search.return_value = GitLabLeaksResult(
            total_count=1,
            items=[
                MagicMock(project_path="group/gl-repo", web_url="...")
            ]
        )
        
        # 3. Mock Repo Analysis
        mock_analyze_repo.return_value = RepoAnalysisResult(
            repository_url="mock_url", total_commits=10, total_committers=1
        )

        # Act
        result = runner.invoke(
            code_intel_app,
            [
                "analyze-repo-leaks",
                "-k", "api_key",
                "-o", "my-org",
                "-g", "my-group",
                "-P", "test_run"
            ]
        )
        
        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        
        # Check that searches were called
        mock_gh_search.assert_called_with(keywords=["api_key"], org_name="my-org")
        mock_gl_search.assert_called_with(keywords=["api_key"], group_name="my-group")
        
        # Check that only the *public* repos were analyzed (Point 4 & 6)
        # Should be 2 calls: 1 for public GH, 1 for GL
        self.assertEqual(mock_analyze_repo.call_count, 2)
        mock_analyze_repo.assert_any_call("https://github.com/org/public-repo")
        mock_analyze_repo.assert_any_call("https://gitlab.com/group/gl-repo.git")
        
        # Check that results were saved separately (Point 5)
        self.assertEqual(mock_save_print.call_count, 2)
        mock_save_print.assert_any_call(unittest.mock.ANY, "test_run_leaks.json", print_to_console=False)
        mock_save_print.assert_any_call(unittest.mock.ANY, "test_run_analysis.json", print_to_console=False)

        # Check that DB saves happened
        self.assertEqual(mock_save_db.call_count, 2) # 2 repo analyses
        mock_save_db.assert_any_call(
            target="https://github.com/org/public-repo",
            module="code_intel_repo_analysis",
            data=unittest.mock.ANY
        )
        mock_save_db.assert_any_call(
            target="https://gitlab.com/group/gl-repo.git",
            module="code_intel_repo_analysis",
            data=unittest.mock.ANY
        )


if __name__ == "__main__":
    unittest.main()