import pytest
import typer
from typer.testing import CliRunner
from unittest.mock import MagicMock, patch 

# The application instance to be tested
from chimera_intel.core.code_intel import code_intel_app

# Create a CliRunner for invoking the app in tests
runner = CliRunner()


@pytest.fixture
def mock_git_repo(mocker):
    """
    A pytest fixture to mock the git.Repo object, preventing actual
    git operations during tests.
    """
    # Mock the commit object
    mock_commit = MagicMock()
    mock_commit.author.name = "John Doe"
    mock_commit.author.email = "john.doe@example.com"
    mock_commit.message = "feat: Add new feature"
    
    # Mock the repo object that `clone_from` would return
    mock_repo_instance = MagicMock()
    mock_repo_instance.iter_commits.return_value = [mock_commit]
    
    # Patch the Repo.clone_from class method to return our mock repo instance
    return mocker.patch("git.Repo.clone_from", return_value=mock_repo_instance)


# Patch external dependencies to prevent unhandled exceptions
@patch("chimera_intel.core.code_intel.save_or_print_results", lambda *_: None)
@patch("chimera_intel.core.code_intel.save_scan_to_db", lambda *_: None)
def test_analyze_repo_command_success(mock_git_repo):
    """
    Tests a successful run of the 'code-intel analyze-repo' command.
    """
    # --- Execute ---
    # The command is 'analyze-repo', with the repository URL as an argument
    result = runner.invoke(
        code_intel_app, ["analyze-repo", "https://github.com/user/repo"]
    )

    # --- Assert ---
    # With patches, exit_code should be 0 (success) as expected
    assert result.exit_code == 0
    # Check for the initial status message
    assert "Analyzing repository: https://github.com/user/repo" in result.stdout
    # Check for the key sections in the output
    assert "Repository Analysis" in result.stdout
    assert "Top Committers" in result.stdout
    assert "John Doe" in result.stdout
    assert "Commit Keyword Analysis" in result.stdout
    assert "'feat': 1" in result.stdout
    
    # Verify that the clone was attempted with the correct URL
    mock_git_repo.assert_called_once()
    assert mock_git_repo.call_args[0][0] == "https://github.com/user/repo"


# Patch external dependencies to prevent unhandled exceptions
@patch("chimera_intel.core.code_intel.save_or_print_results", lambda *_: None)
@patch("chimera_intel.core.code_intel.save_scan_to_db", lambda *_: None)
def test_analyze_repo_command_clone_error(mocker):
    """
    Tests how the command handles an error during the git clone process.
    """
    # --- Arrange ---
    # Configure the mock to raise an Exception, simulating a failed clone
    mocker.patch(
        "git.Repo.clone_from",
        side_effect=Exception("fatal: repository not found"),
    )

    # --- Execute ---
    result = runner.invoke(
        code_intel_app, ["analyze-repo", "https://github.com/user/nonexistent-repo"]
    )

    # --- Assert ---
    # Check the exception for the correct exit code
    exit_code = result.exit_code
    if isinstance(result.exception, typer.Exit):
        exit_code = result.exception.exit_code

    assert exit_code == 1
    # Check for the specific error message in the output
    assert "Failed to clone or analyze repository" in result.stdout
    assert "fatal: repository not found" in result.stdout