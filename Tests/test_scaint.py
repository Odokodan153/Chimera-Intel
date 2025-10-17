import pytest
from typer.testing import CliRunner
import json
import git

# The application instance to be tested

from chimera_intel.core.scaint import scaint_app

runner = CliRunner()


@pytest.fixture
def mock_git_clone(mocker):
    """Mocks the git.Repo.clone_from call."""
    return mocker.patch("git.Repo.clone_from")


@pytest.fixture
def mock_subprocess_run(mocker):
    """Mocks the subprocess.run call."""
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
    """
    Tests the analyze-repo command with a successful analysis.
    """
    # Mock os.path.exists to simulate the presence of requirements.txt

    mocker.patch("os.path.exists", return_value=True)

    result = runner.invoke(
        scaint_app,
        ["analyze-repo", "--repo-url", "https://github.com/some/repo"],
    )

    assert result.exit_code == 0
    assert "Analyzing repository: https://github.com/some/repo" in result.stdout
    assert "Cloning repository" in result.stdout
    assert "Scanning for known vulnerabilities..." in result.stdout
    assert "Package: requests@2.25.1" in result.stdout
    assert "ID: CVE-2023-32681" in result.stdout


def test_analyze_repo_no_requirements_txt(mocker, mock_git_clone):
    """
    Tests the analyze-repo command when requirements.txt is not found.
    """
    mocker.patch("os.path.exists", return_value=False)

    result = runner.invoke(
        scaint_app,
        ["analyze-repo", "--repo-url", "https://github.com/some/repo"],
    )

    assert result.exit_code == 1
    assert (
        "Analysis Error: requirements.txt not found in the repository." in result.stdout
    )


def test_analyze_repo_git_clone_fails(mocker, mock_git_clone):
    """
    Tests the analyze-repo command when git clone fails.
    """
    # GitCommandError requires cmd, status, and stderr

    mock_git_clone.side_effect = git.exc.GitCommandError(
        "clone", 1, stderr="mock error"
    )
    result = runner.invoke(
        scaint_app,
        ["analyze-repo", "--repo-url", "https://github.com/some/repo"],
    )
    assert result.exit_code == 1
    # The actual error message from GitCommandError includes the command and exit code.
    # We'll check for the stderr part we provided.

    assert "mock error" in result.stdout
