import typer
from typer.testing import CliRunner
import json
from unittest.mock import MagicMock, patch 

# The application instance to be tested
from chimera_intel.core.code_intel import code_intel_app

# Create a CliRunner for invoking the app in tests
runner = CliRunner()


# The mock_git_repo fixture is no longer needed, as we will patch directly.

# Patch external dependencies
@patch("git.Repo.clone_from")
# We REMOVE the patch for save_or_print_results so the stdout assertions can pass
# --- FIX: Updated lambda to accept *args and **kwargs ---
@patch("chimera_intel.core.code_intel.save_scan_to_db", lambda *args, **kwargs: None)
def test_analyze_repo_command_success(mock_clone):
    """
    Tests a successful run of the 'code-intel analyze-repo' command.
    """
    # --- Arrange ---
    # Mock the commit object
    mock_commit = MagicMock()
    mock_commit.author.name = "John Doe"
    mock_commit.author.email = "john.doe@example.com"
    mock_commit.message = "feat: Add new feature"
    
    # Mock the repo object that `clone_from` would return
    mock_repo_instance = MagicMock()
    mock_repo_instance.iter_commits.return_value = [mock_commit]
    
    # Configure the mock passed in by the decorator
    mock_clone.return_value = mock_repo_instance

    # --- Execute ---
    # FIXED: Remove "analyze-repo" from the list.
    # The app *is* the analyze-repo command.
    result = runner.invoke(
        code_intel_app, ["https://github.com/user/repo"]
    )

    # --- Assert ---
    # With patches, exit_code should be 0 (success) as expected
    assert result.exit_code == 0
    
    # Check for the initial status message
    assert "Analyzing repository: https://github.com/user/repo" in result.stdout
    
    # --- FIX: Assert against the actual JSON output format ---
    # The CLI prints a status message first, followed by the JSON output.
    output_lines = result.stdout.splitlines()
    json_output = "\n".join(output_lines[1:])

    try:
        data = json.loads(json_output)
    except json.JSONDecodeError as e:
        assert False, f"Output is not valid JSON: {json_output}. Error: {e}"

    assert data["repository_url"] == "https://github.com/user/repo"
    assert data["total_commits"] == 1
    assert data["total_committers"] == 1
    assert data["top_committers"][0]["name"] == "John Doe"
    assert data["commit_keywords"]["feat"] == 1
    # --- END FIX ---
    
    # Verify that the clone was attempted with the correct URL
    mock_clone.assert_called_once()
    assert mock_clone.call_args[0][0] == "https://github.com/user/repo"


# Patch external dependencies and the clone_from method to raise an error
@patch("git.Repo.clone_from", side_effect=Exception("fatal: repository not found"))
# This patch isn't strictly needed here as this code path doesn't save,
# but we leave it for consistency.
# --- FIX: Updated lambda to accept *args and **kwargs ---
@patch("chimera_intel.core.code_intel.save_scan_to_db", lambda *args, **kwargs: None)
def test_analyze_repo_command_clone_error(mock_clone):
    """
    Tests how the command handles an error during the git clone process.
    """
    # --- Arrange ---
    # The mock_clone decorator is already configured to raise the exception.

    # --- Execute ---
    # FIXED: Remove "analyze-repo" from the list.
    result = runner.invoke(
        code_intel_app, ["https://github.com/user/nonexistent-repo"]
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