"""
Tests for the The Eye API Router
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock

# Must mock TheEye before importing the app
@pytest.fixture(autouse=True)
def mock_the_eye():
    mock = MagicMock()
    mock.return_value.check_system_health.return_value = MagicMock(healthy=True)
    mock.return_value.run = AsyncMock()
    
    with patch("chimera_intel.webapp.routers.the_eye_api.TheEye", mock):
        yield mock

# Now import the app
from chimera_intel.webapp.main import app

@pytest.fixture
def client():
    return TestClient(app)

def test_get_system_health_healthy(client):
    response = client.get("/api/v1/eye/health")
    assert response.status_code == 200
    assert response.json()["healthy"] is True

def test_start_investigation(client):
    with patch("chimera_intel.webapp.routers.the_eye_api.BackgroundTasks.add_task") as mock_add_task:
        response = client.post(
            "/api/v1/eye/run",
            json={"identifier": "acme.com", "tenant_id": "test_tenant"}
        )
        assert response.status_code == 202
        assert response.json()["run_id"] == "test_tenant:acme.com"
        # Check that the background task was correctly added
        mock_add_task.assert_called_once()
        assert mock_add_task.call_args[0][1] == "acme.com" # identifier
        assert mock_add_task.call_args[0][2] == "test_tenant" # tenant_id