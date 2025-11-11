# Save as: Chimera-Intel/Tests/test_grey_literature.py

import pytest
import json
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from chimera_intel.core.grey_literature import grey_lit_app
from chimera_intel.core.schemas import GreyLitOverallResult

runner = CliRunner()

# Mock Google Custom Search API response
MOCK_API_RESPONSE = {
    "items": [
        {
            "title": "Test Report 1",
            "link": "https://example.gov/report1.pdf",
            "displayLink": "example.gov",
            "snippet": "This is a test PDF report snippet.",
            "fileFormat": "application/pdf"
        },
        {
            "title": "Test Presentation 2",
            "link": "https://example.org/report2.pptx",
            "displayLink": "example.org",
            "snippet": "This is a test PPTX snippet.",
            "fileFormat": "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        },
        {
            "title": "Test HTML Page",
            "link": "https://example.com/page.html",
            "displayLink": "example.com",
            "snippet": "This is a regular web page.",
            "fileFormat": "HTML"
        }
    ]
}


@pytest.fixture
def mock_api_keys():
    """Mocks API keys for the duration of a test."""
    with patch("chimera_intel.core.grey_literature.API_KEYS", {"google_api_key": "fake_key", "google_cse_id": "fake_cse_id"}):
        yield

@patch("chimera_intel.core.grey_literature.sync_client.get")
def test_cli_search_success(mock_get, mock_api_keys):
    """Tests the 'search' command with a successful API response."""
    
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = MOCK_API_RESPONSE
    mock_get.return_value = mock_response
    
    result = runner.invoke(
        grey_lit_app,
        [
            "search",
            "test query",
            "--filetype", "pdf",
            "--filetype", "pptx",
            "--domain", "gov",
            "--domain", "org",
        ],
    )

    assert result.exit_code == 0
    assert "Found 2 relevant documents" in result.stdout
    assert "Test Report 1" in result.stdout
    assert "Test Presentation 2" in result.stdout
    # The HTML page should be filtered out
    assert "Test HTML Page" not in result.stdout

    # Check that the API was called with the correct query
    mock_get.assert_called_once()
    api_call_params = mock_get.call_args[1].get("params", {})
    assert "filetype:pdf OR filetype:pptx" in api_call_params.get("q")
    assert "site:.gov OR site:.org" in api_call_params.get("q")
    
@patch("chimera_intel.core.grey_literature.sync_client.get")
def test_cli_search_api_failure(mock_get, mock_api_keys):
    """Tests the 'search' command when the API call fails."""
    
    mock_get.side_effect = Exception("API is down")
    
    result = runner.invoke(
        grey_lit_app,
        ["search", "test query"],
    )

    assert result.exit_code == 1
    assert "Error" in result.stdout
    assert "An API error occurred" in result.stdout

def test_cli_search_no_api_keys():
    """Tests the 'search' command when API keys are missing."""
    # Patch API_KEYS to be an empty dict
    with patch("chimera_intel.core.grey_literature.API_KEYS", {}):
        result = runner.invoke(
            grey_lit_app,
            ["search", "test query"],
        )

        assert result.exit_code == 1
        assert "Error" in result.stdout
        assert "GOOGLE_API_KEY and GOOGLE_CSE_ID must be set" in result.stdout