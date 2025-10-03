import pytest
from unittest.mock import AsyncMock, patch
from typer.testing import CliRunner
import json
from src.chimera_intel.core.spaceint import spaceint_app, track_satellites
from src.chimera_intel.core.schemas import SPACEINTResult, TLEData

# Standard Pytest CLI runner setup
runner = CliRunner()

# --- Mock Data ---
MOCK_ISS_TLE_RAW = """
1 25544U 98067A   24276.01234567  .00000000  00000-0  00000+0 0  9999
2 25544  51.6413 245.9221 0006703 260.5501 199.4560 15.49442085420000
"""
MOCK_TLE_NO_DATA = ""


@pytest.mark.asyncio
async def test_track_satellites_success():
    """Tests successful retrieval and parsing of TLE data."""
    # Mock the async HTTP client's 'get' method
    with patch("src.chimera_intel.core.spaceint.async_client") as mock_client:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.text = MOCK_ISS_TLE_RAW
        mock_client.get.return_value = mock_response

        # Call the actual async function
        norad_id = "25544"
        result = await track_satellites(norad_id=norad_id)

        assert isinstance(result, SPACEINTResult)
        assert result.total_satellites == 1
        assert result.satellites[0].norad_id == norad_id
        # Check TLE line 1 data structure
        assert result.satellites[0].line1.startswith("1 25544U")
        assert result.satellites[0].line2.startswith("2 25544")


@pytest.mark.asyncio
async def test_track_satellites_no_data():
    """Tests handling an empty response from the TLE API."""
    with patch("src.chimera_intel.core.spaceint.async_client") as mock_client:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.text = MOCK_TLE_NO_DATA
        mock_client.get.return_value = mock_response

        result = await track_satellites(norad_id="999999")

        assert result.total_satellites == 0
        assert "returned insufficient TLE data" in result.error

# --- CLI Tests ---

# Mock the internal async function for fast CLI testing
@patch("src.chimera_intel.core.spaceint.track_satellites")
def test_spaceint_cli_success(mock_track_satellites, tmp_path):
    """Tests the 'spaceint track' CLI command with successful data."""
    norad_id = "25544"
    mock_result = SPACEINTResult(
        total_satellites=1, 
        satellites=[TLEData(norad_id=norad_id, line1=MOCK_ISS_TLE_RAW.split('\n')[1].strip(), line2=MOCK_ISS_TLE_RAW.split('\n')[2].strip())]
    )
    mock_track_satellites.return_value = mock_result
    
    output_file = tmp_path / "tle_results.json"
    
    result = runner.invoke(spaceint_app, ["track", "--norad-id", norad_id, "-o", str(output_file)])

    assert result.exit_code == 0
    assert f"Tracking Satellite: NORAD ID: {norad_id}" in result.output
    
    # Check that the mock was called correctly
    mock_track_satellites.assert_called_once_with(norad_id=norad_id)
    
    # Check output file content
    with open(output_file, 'r') as f:
        data = json.load(f)
        assert data['total_satellites'] == 1
        assert data['satellites'][0]['norad_id'] == norad_id