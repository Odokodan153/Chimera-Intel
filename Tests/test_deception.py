import pytest
import typer  
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# The application instance to be tested
from chimera_intel.core.deception import deception_app

runner = CliRunner()

# FIX 2: Wrap the sub-app in a parent app
app = typer.Typer()
app.add_typer(deception_app, name="deception")


@pytest.fixture
def mock_docker_client(mocker):
    """Mocks the docker.from_env() client."""
    mock_container = MagicMock()
    mock_container.short_id = "a1b2c3d4"

    mock_client = MagicMock()
    mock_client.ping.return_value = True  # <-- FIX 3: Add mock for client.ping()
    mock_client.images.pull.return_value = None
    mock_client.containers.run.return_value = mock_container

    # Patch the docker import *where it's used* (in the deception module)
    return mocker.patch("chimera_intel.core.deception.docker.from_env", return_value=mock_client)


def test_deploy_honeypot_success(mock_docker_client):
    """
    Tests the successful deployment of an SSH honeypot.
    """
    # FIX 2: Invoke the parent app with the full command
    result = runner.invoke(
        app,
        ["deception", "deploy-honeypot", "--type", "ssh", "--port", "2222"],
    )

    assert result.exit_code == 0, result.output
    assert "Honeypot deployed successfully!" in result.stdout
    assert "Container ID: a1b2c3d4" in result.stdout
    assert "docker logs -f a1b2c3d4" in result.stdout

    # Verify that the docker client was called correctly
    # Get the mock client instance from the fixture
    mock_client_instance = mock_docker_client.return_value
    mock_client_instance.images.pull.assert_called_with("cowrie/cowrie")
    mock_client_instance.containers.run.assert_called_with(
        image="cowrie/cowrie",
        detach=True,
        ports={"2222/tcp": 2222},
        name="chimera-honeypot-ssh-2222",
    )


def test_deploy_honeypot_unsupported_type():
    """
    Tests the command's failure with an unsupported honeypot type.
    """
    # FIX 2: Invoke the parent app with the full command
    result = runner.invoke(
        app,
        ["deception", "deploy-honeypot", "--type", "http", "--port", "8080"],
    )

    assert result.exit_code != 0
    # FIX 4: Use substring match to ignore rich markup
    assert "Honeypot type 'http' is not supported" in result.stdout


@patch("chimera_intel.core.deception.docker.from_env")
def test_deploy_honeypot_docker_error(mock_from_env):
    """
    Tests the command's error handling when the Docker daemon is not available.
    """
    # Simulate a DockerException
    from docker.errors import DockerException

    mock_from_env.side_effect = DockerException("Docker daemon not found.")

    # FIX 2: Invoke the parent app with the full command
    result = runner.invoke(
        app,
        ["deception", "deploy-honeypot", "--type", "ssh", "--port", "2222"],
    )

    assert result.exit_code != 0
    # FIX 4: Use substring match to ignore rich markup
    assert "Docker Error: Could not connect to the Docker daemon" in result.stdout