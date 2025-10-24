import pytest
from typer.testing import CliRunner
import git
import json
from chimera_intel.core.scaint import scaint_app

runner = CliRunner()


@pytest.fixture
def mock_git_clone(mocker):
    """Mocks git.Repo.clone_from to avoid real cloning."""
    return mocker.patch("git.Repo.clone_from")


@pytest.fixture
def mock_subprocess_run(mocker):
    """Mocks subprocess.run to simulate OSV-Scanner output."""
    mock_result = mocker.MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps(
        {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "requests", "version": "2.25.1"},
                            "vulnerabilities": [
                                {
                                    "id": "CVE-2023-32681",
                                    "summary": "A vulnerability in requests",
                                    "severity": "HIGH",
                                }
                            ],
                        }
                    ]
                }
            ]
        }
    )
    mock_result.stderr = ""
    return mocker.patch("subprocess.run", return_value=mock_result)


def test_analyze_repo_success(mocker, mock_git_clone, mock_subprocess_run):
    """Analyze repo successfully with vulnerabilities."""
    mocker.patch("os.path.exists", return_value=True)

    # --- FIX: Pass 'repo_url' as a positional argument, not an option ---
    result = runner.invoke(
        scaint_app, ["analyze-repo", "https://github.com/some/repo"]
    )
    # --- END FIX ---

    assert result.exit_code == 0, result.stdout
    assert "Analyzing repository: https://github.com/some/repo" in result.stdout
    assert "Cloning repository" in result.stdout
    assert "Scanning for known vulnerabilities..." in result.stdout
    assert "Package: requests@2.25.1" in result.stdout
    assert "ID: CVE-2023-32681" in result.stdout


def test_analyze_repo_no_requirements_txt(mocker, mock_git_clone):
    """Fails if requirements.txt is missing."""
    mocker.patch("os.path.exists", return_value=False)

    # --- FIX: Pass 'repo_url' as a positional argument, not an option ---
    result = runner.invoke(
        scaint_app, ["analyze-repo", "https://github.com/some/repo"]
    )
    # --- END FIX ---

    assert result.exit_code == 1, result.stdout
    assert (
        "Analysis Error: requirements.txt not found in the repository." in result.stdout
    )


def test_analyze_repo_git_clone_fails(mocker, mock_git_clone):
    """Fails if git clone fails."""
    mock_git_clone.side_effect = git.exc.GitCommandError(
        "clone", 1, stderr="mock error"
    )

    # --- FIX: Pass 'repo_url' as a positional argument, not an option ---
    result = runner.invoke(
        scaint_app, ["analyze-repo", "https://github.com/some/repo"]
    )
    # --- END FIX ---

    assert result.exit_code == 1, result.stdout
    assert "Error cloning repository" in result.stdout
    assert "mock error" in result.stdout