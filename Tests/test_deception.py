import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# The application instance to be tested

from chimera_intel.core.deception import deception_app

runner = CliRunner()


@pytest.fixture
def mock_docker_client(mocker):
    """Mocks the docker.from_env() client."""
    mock_container = MagicMock()
    mock_container.short_id = "a1b2c3d4"

    mock_client = MagicMock()
    mock_client.images.pull.return_value = None
    mock_client.containers.run.return_value = mock_container

    return mocker.patch("docker.from_env", return_value=mock_client)


def test_deploy_honeypot_success(mock_docker_client):
    """
    Tests the successful deployment of an SSH honeypot.
    """
    result = runner.invoke(
        deception_app,
        ["deploy-honeypot", "--type", "ssh", "--port", "2222"],
    )

    assert result.exit_code == 0
    assert "Honeypot deployed successfully!" in result.stdout
    assert "Container ID: a1b2c3d4" in result.stdout
    assert "docker logs -f a1b2c3d4" in result.stdout

    # Verify that the docker client was called correctly

    mock_docker_client.images.pull.assert_called_with("cowrie/cowrie")
    mock_docker_client.containers.run.assert_called_with(
        image="cowrie/cowrie",
        detach=True,
        ports={"2222/tcp": 2222},
        name="chimera-honeypot-ssh-2222",
    )


def test_deploy_honeypot_unsupported_type():
    """
    Tests the command's failure with an unsupported honeypot type.
    """
    result = runner.invoke(
        deception_app,
        ["deploy-honeypot", "--type", "http", "--port", "8080"],
    )

    assert result.exit_code != 0
    assert "Error: Honeypot type 'http' is not supported." in result.stdout


@patch("docker.from_env")
def test_deploy_honeypot_docker_error(mock_from_env):
    """
    Tests the command's error handling when the Docker daemon is not available.
    """
    # Simulate a DockerException

    from docker.errors import DockerException

    mock_from_env.side_effect = DockerException("Docker daemon not found.")

    result = runner.invoke(
        deception_app,
        ["deploy-honeypot", "--type", "ssh", "--port", "2222"],
    )

    assert result.exit_code != 0
    assert "Docker Error: Could not connect to the Docker daemon." in result.stdout