import unittest
from unittest.mock import patch, MagicMock
from chimera_intel.core.code_intel import analyze_git_repository
from chimera_intel.core.schemas import RepoAnalysisResult


class TestCodeIntel(unittest.TestCase):
    """Test cases for the code_intel module."""

    @patch("chimera_intel.core.code_intel.shutil.rmtree")
    @patch("chimera_intel.core.code_intel.git.Repo.clone_from")
    def test_analyze_git_repository_success(self, mock_clone_from, mock_rmtree):
        """Tests a successful repository analysis by mocking the git clone."""
        # Arrange

        mock_repo = MagicMock()

        # Create mock commit objects

        mock_author1 = MagicMock(name="Jane Doe", email="jane@example.com")
        mock_commit1 = MagicMock(
            author=mock_author1, message="feat: Add new dashboard feature"
        )

        mock_author2 = MagicMock(name="John Smith", email="john@example.com")
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
        mock_rmtree.assert_called_once()  # Verify cleanup was called


if __name__ == "__main__":
    unittest.main()
