"""
Tests for the Zero-Day Tracking module.

This test file has been updated to mock the NVD API 2.0,
which the 'monitor_emerging_exploits' function now uses.
"""

import pytest
import httpx
from pytest_mock import MockerFixture
from chimera_intel.core.zero_day_tracking import monitor_emerging_exploits
from chimera_intel.core.schemas import ZeroDayTrackingResult
from chimera_intel.core import config_loader

# A mock NVD 2.0 API response for a CVE that is in CISA's KEV catalog
MOCK_NVD_RESPONSE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2025-12345",
                "sourceIdentifier": "test@nvd.nist.gov",
                "published": "2025-11-15T01:00:00.000",
                "lastModified": "2025-11-15T02:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "This is a test vulnerability description."
                    },
                    {
                        "lang": "es",
                        "value": "Esta es una descripción de vulnerabilidad de prueba."
                    }
                ],
                "references": [
                    {
                        "url": "https://example.com/advisory/1",
                        "source": "example.com"
                    }
                ],
                "exploitAdd": "2025-11-16" # Presence of this key means it's in CISA KEV
            }
        }
    ]
}

# A mock response for when no vulnerabilities are found
MOCK_NVD_RESPONSE_NONE = {
    "resultsPerPage": 0,
    "startIndex": 0,
    "totalResults": 0,
    "vulnerabilities": []
}


def test_monitor_emerging_exploits_success(mocker: MockerFixture):
    """
    Test a successful query to the NVD API.
    """
    # Mock the API_KEYS
    mocker.patch.object(config_loader.API_KEYS, "exploit_feed_api_key", "fake-nvd-api-key")
    
    # Mock the httpx response
    mock_response = mocker.Mock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = MOCK_NVD_RESPONSE
    mock_response.raise_for_status.return_value = None
    
    # Mock the sync_client.get call
    mock_get = mocker.patch(
        "chimera_intel.core.zero_day_tracking.sync_client.get",
        return_value=mock_response
    )
    
    # Run the function
    query = "test query"
    result = monitor_emerging_exploits(query)
    
    # Assertions
    assert result.error is None
    assert result.query == query
    assert len(result.emerging_exploits) == 1
    assert result.summary == "Found 1 CVEs matching 'test query'."
    
    exploit = result.emerging_exploits[0]
    assert exploit.exploit_id == "CVE-2025-12345"
    assert exploit.description == "This is a test vulnerability description."
    assert exploit.discovered_on == "2025-11-15T01:00:00.000"
    assert exploit.source_url == "https://example.com/advisory/1"
    assert exploit.is_zero_day is True # is_zero_day is flagged True due to 'exploitAdd'
    assert exploit.product == "N/A"
    assert exploit.vendor == "N/A"
    
    # Check if httpx.get was called correctly
    mock_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        headers={"apiKey": "fake-nvd-api-key"},
        params={"keywordSearch": query, "resultsPerPage": 20}
    )

def test_monitor_emerging_exploits_no_key(mocker: MockerFixture):
    """
    Test failure when the NVD API key is not configured.
    """
    # Mock the API_KEYS to have no key
    mocker.patch.object(config_loader.API_KEYS, "exploit_feed_api_key", None)
    
    result = monitor_emerging_exploits("test query")
    
    assert result.error is not None
    assert "NVD API key" in result.error
    assert len(result.emerging_exploits) == 0

def test_monitor_emerging_exploits_not_found(mocker: MockerFixture):
    """
    Test a successful query that returns no results.
    """
    mocker.patch.object(config_loader.API_KEYS, "exploit_feed_api_key", "fake-nvd-api-key")
    
    mock_response = mocker.Mock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = MOCK_NVD_RESPONSE_NONE
    mock_response.raise_for_status.return_value = None
    
    mocker.patch(
        "chimera_intel.core.zero_day_tracking.sync_client.get",
        return_value=mock_response
    )
    
    result = monitor_emerging_exploits("query with no results")
    
    assert result.error is None
    assert len(result.emerging_exploits) == 0
    assert "No CVEs found" in result.summary

def test_monitor_emerging_exploits_api_error(mocker: MockerFixture):
    """
    Test an HTTP error from the NVD API.
    """
    mocker.patch.object(config_loader.API_KEYS, "exploit_feed_api_key", "fake-nvd-api-key")
    
    # Mock the client to raise an exception
    mocker.patch(
        "chimera_intel.core.zero_day_tracking.sync_client.get",
        side_effect=httpx.RequestError("Mocked API Failure")
    )
    
    result = monitor_emerging_exploits("test query")
    
    assert result.error is not None
    assert "An API error occurred" in result.error
    assert "Mocked API Failure" in result.error
    assert len(result.emerging_exploits) == 0