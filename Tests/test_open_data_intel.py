import pytest
from unittest.mock import patch, MagicMock
from chimera_intel.core.open_data_intel import get_world_bank_indicator
from chimera_intel.core.schemas import OpenDataResult

# Mock data for a successful World Bank API response
MOCK_WB_RESPONSE = [
    {
        "page": 1,
        "pages": 1,
        "per_page": 50,
        "total": 1,
        "sourceid": "2",
        "lastupdated": "2024-10-30",
    },
    [
        {
            "indicator": {"id": "NY.GDP.MKTP.CD", "value": "GDP (current US$)"},
            "country": {"id": "WLD", "value": "World"},
            "countryiso3code": "WLD",
            "date": "2022",
            "value": 100562013997003.0,
            "unit": "",
            "obs_status": "",
            "decimal": 0,
            "sourceID": "2",
            "lastupdated": "2024-03-01",
        }
    ],
]


@patch("chimera_intel.core.open_data_intel.sync_client.get")
def test_get_world_bank_indicator_success(mock_get):
    """Tests a successful query to the World Bank API."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = MOCK_WB_RESPONSE
    mock_get.return_value = mock_response

    indicator = "NY.GDP.MKTP.CD"
    country = "WLD"
    result = get_world_bank_indicator(indicator, country)

    assert isinstance(result, OpenDataResult)
    assert result.error is None
    assert result.total_results == 1
    assert result.data_points[0].indicator == "GDP (current US$)"
    assert result.data_points[0].country == "World"
    assert result.data_points[0].value == 100562013997003.0

    mock_get.assert_called_once_with(
        "https://api.worldbank.org/v2/country/WLD/indicator/NY.GDP.MKTP.CD",
        params={
            "format": "json",
            "per_page": 50,
            "date": "1960:2025",
            "MRV": 50,
        },
    )


@patch("chimera_intel.core.open_data_intel.sync_client.get")
def test_get_world_bank_indicator_no_data(mock_get):
    """Tests a query that returns no data."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    # Mock response format for "no data found"
    mock_response.json.return_value = [
        {"page": 1, "pages": 0, "per_page": 50, "total": 0},
        None,
    ]
    mock_get.return_value = mock_response

    result = get_world_bank_indicator("INVALID.CODE", "USA")

    assert isinstance(result, OpenDataResult)
    assert result.error == "No data found or malformed API response."
    assert result.total_results == 0
    assert len(result.data_points) == 0


@patch("chimera_intel.core.open_data_intel.sync_client.get")
def test_get_world_bank_indicator_api_error(mock_get):
    """Tests a failure due to an HTTP error."""
    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = Exception("API 404 Error")
    mock_get.return_value = mock_response

    result = get_world_bank_indicator("NY.GDP.MKTP.CD", "WLD")

    assert isinstance(result, OpenDataResult)
    assert "An API error occurred" in result.error
    assert result.total_results == 0