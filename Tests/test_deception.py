import pytest
import typer
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import docker.errors  # Import the actual exceptions for side_effect

# The application instance to be tested
from chimera_intel.core.deception import deception_app

runner = CliRunner()

# Wrap the sub-app in a parent app
app = typer.Typer()
app.add_typer(deception_app, name="deception")


@pytest.fixture
def mock_docker_client(mocker):
    """Mocks the docker.from_env() client."""
    mock_container = MagicMock()
    mock_container.short_id = "a1b2c3d4"
    
    mock_existing_container = MagicMock()

    mock_client = MagicMock()
    mock_client.ping.return_value = True
    
    # Default: Simulate no existing container and image not found
    mock_client.containers.get.side_effect = docker.errors.NotFound("not found")
    mock_client.images.get.side_effect = docker.errors.ImageNotFound("not found")
    
    mock_client.images.pull.return_value = None
    mock_client.containers.run.return_value = mock_container
    
    # Mock the specific container methods
    mock_client.containers.get.return_value = mock_existing_container
    
    # Patch the docker import *where it's used* (in the deception module)
    return mocker.patch(
        "chimera_intel.core.deception.docker.from_env", return_value=mock_client
    )


def test_deploy_honeypot_success(mock_docker_client):
    """
    Tests the successful deployment (default case: no existing container, needs pull).
    """
    # Setup mocks for this test case
    mock_client = mock_docker_client.return_value
    mock_client.containers.get.side_effect = docker.errors.NotFound("not found")
    mock_client.images.get.side_effect = docker.errors.ImageNotFound("not found")
    
    result = runner.invoke(
        app,
        ["deception", "deploy-honeypot", "--type", "ssh", "--port", "2222"],
    )

    assert result.exit_code == 0, result.output
    assert "Honeypot deployed successfully!" in result.stdout
    assert "Container ID: a1b2c3d4" in result.stdout

    # Verify new checks
    mock_client.containers.get.assert_called_with("chimera-honeypot-ssh-2222")
    mock_client.images.get.assert_called_with("cowrie/cowrie")
    
    # Verify image was pulled
    mock_client.images.pull.assert_called_with("cowrie/cowrie")
    
    # Verify container was run
    mock_client.containers.run.assert_called_with(
        image="cowrie/cowrie",
        detach=True,
        ports={"2222/tcp": 2222},
        name="chimera-honeypot-ssh-2222",
    )


def test_deploy_honeypot_handles_existing_container(mock_docker_client):
    """
    Tests that an existing container is correctly stopped and removed.
    """
    mock_client = mock_docker_client.return_value
    mock_existing_container = MagicMock()
    
    # Setup mocks: Container *is* found
    mock_client.containers.get.return_value = mock_existing_container
    mock_client.containers.get.side_effect = None # Clear side_effect
    
    result = runner.invoke(
        app,
        ["deception", "deploy-honeypot", "--type", "telnet", "--port", "2323"],
    )
    
    assert result.exit_code == 0, result.output
    assert "Found existing container" in result.stdout
    
    # Verify it was stopped and removed
    mock_existing_container.stop.assert_called_once()
    mock_existing_container.remove.assert_called_once()
    
    # Verify the new container was still run
    mock_client.containers.run.assert_called_with(
        image="cowrie/cowrie",
        detach=True,
        ports={"2223/tcp": 2323}, # Correct internal port for telnet
        name="chimera-honeypot-telnet-2323",
    )


def test_deploy_honeypot_skips_pull_if_image_exists(mock_docker_client):
    """
    Tests that image pull is skipped if the image is found locally.
    """
    mock_client = mock_docker_client.return_value
    mock_image = MagicMock()
    
    # Setup mocks: Container not found, but Image *is* found
    mock_client.containers.get.side_effect = docker.errors.NotFound("not found")
    mock_client.images.get.return_value = mock_image
    mock_client.images.get.side_effect = None # Clear side_effect
    
    result = runner.invoke(
        app,
        ["deception", "deploy-honeypot", "--type", "ssh", "--port", "2222"],
    )
    
    assert result.exit_code == 0, result.output
    assert "Image 'cowrie/cowrie' already exists locally" in result.stdout
    
    # Verify pull was *not* called
    mock_client.images.pull.assert_not_called()
    
    # Verify container was still run
    mock_client.containers.run.assert_called_once()


def test_deploy_honeypot_unsupported_type():
    """
    Tests the command's failure with an unsupported honeypot type.
    """
    result = runner.invoke(
        app,
        ["deception", "deploy-honeypot", "--type", "http", "--port", "8080"],
    )

    assert result.exit_code != 0
    assert "Honeypot type 'http' is not supported" in result.stdout


@patch("chimera_intel.core.deception.docker.from_env")
def test_deploy_honeypot_docker_error(mock_from_env):
    """
    Tests the command's error handling when the Docker daemon is not available.
    """
    mock_from_env.side_effect = docker.errors.DockerException("Docker daemon not found.")

    result = runner.invoke(
        app,
        ["deception", "deploy-honeypot", "--type", "ssh", "--port", "2222"],
    )

    assert result.exit_code != 0
    assert "Docker Error: Could not connect to the Docker daemon" in result.stdout