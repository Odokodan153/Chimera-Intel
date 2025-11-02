import pytest
from unittest.mock import patch, MagicMock, Mock
from unittest.mock import MagicMock
import typer  # Import the main Typer library
from chimera_intel.core.infrastructure_intel import (
    infrastructure_intel_app,
    find_nearby_substations,
    find_nearby_cell_towers,
    find_nearby_water_sources,
    find_nearby_airports,
    find_nearby_ports,
)
from typer.testing import CliRunner
from chimera_intel.core.infrastructure_intel import infrastructure_intel_app

runner = CliRunner()

# FIX: Wrap the sub-app in a parent Typer for correct test invocation
app = typer.Typer()
app.add_typer(infrastructure_intel_app, name="infra")


@pytest.fixture
def mock_geolocator(mocker):
    """Mocks the geopy.geocoders.Nominatim call."""
    mock_location = mocker.MagicMock()
    mock_location.latitude = 34.0522
    mock_location.longitude = -118.2437
    mocker.patch("geopy.geocoders.Nominatim.geocode", return_value=mock_location)


@pytest.fixture
def mock_overpass(mocker):
    """Mocks the overpy.Overpass API call."""
    mock_result = MagicMock()
    mock_node = MagicMock()
    mock_node.tags = {"name": "Main Substation", "operator": "City Power"}
    mock_node.lat = 34.0500
    mock_node.lon = -118.2500
    mock_result.nodes = [mock_node]
    mocker.patch("overpy.Overpass.query", return_value=mock_result)


def test_infrastructure_dependency_success(mocker, mock_geolocator, mock_overpass):
    """
    Tests the infrastructure-dependency command with a successful analysis.
    """
    # FIX: Invoke the parent app with the full command path
    result = runner.invoke(
        app,
        ["infra", "analyze", "123 Main St, Anytown, USA"],
    )

    assert result.exit_code == 0
    assert (
        "Analyzing infrastructure dependencies for: 123 Main St, Anytown, USA"
        in result.stdout
    )
    assert "Coordinates found: Latitude=34.0522" in result.stdout
    assert "Nearby Electrical Substations" in result.stdout
    assert "Name: Main Substation, Operator: City Power" in result.stdout


def test_infrastructure_dependency_no_geocode(mocker):
    """
    Tests the command when the address cannot be geocoded.
    """
    mocker.patch("geopy.geocoders.Nominatim.geocode", return_value=None)

    # FIX: Invoke the parent app with the full command path
    result = runner.invoke(
        app,
        ["infra", "analyze", "unknown address"],
    )

    assert result.exit_code == 1
    assert "Error: Could not geocode the address 'unknown address'." in result.stdout


@pytest.fixture
def mock_overpass_api():
    """Mocks the overpy.Overpass API and its query result."""
    mock_api = MagicMock()
    mock_result = MagicMock()

    # Mock data for nodes and ways
    mock_node = Mock()
    mock_node.is_node = True
    mock_node.tags = {"name": "Test Node", "operator": "TestOp"}
    mock_node.lat = 10.0
    mock_node.lon = 20.0

    mock_way = Mock()
    mock_way.is_node = False
    mock_way.tags = {"name": "Test Way"}
    mock_way.center_lat = 10.1
    mock_way.center_lon = 20.1

    mock_result.nodes = [mock_node]
    mock_result.ways = [mock_way]
    mock_api.query.return_value = mock_result
    return mock_api


@pytest.fixture
def mock_geolocator():
    """Mocks the Nominatim geolocator."""
    with patch("geopy.geocoders.Nominatim") as mock_geo_class:
        mock_geolocator_instance = MagicMock()
        mock_location = MagicMock()
        mock_location.latitude = 40.7128
        mock_location.longitude = -74.0060
        mock_geolocator_instance.geocode.return_value = mock_location
        mock_geo_class.return_value = mock_geolocator_instance
        yield mock_geolocator_instance


@patch("overpy.Overpass")
def test_find_nearby_substations(MockOverpass, mock_overpass_api):
    MockOverpass.return_value = mock_overpass_api
    results = find_nearby_substations(mock_overpass_api, 10.0, 20.0)
    assert len(results) == 1
    assert results[0]["name"] == "Test Node"
    assert results[0]["operator"] == "TestOp"


@patch("overpy.Overpass")
def test_find_nearby_water_sources(MockOverpass, mock_overpass_api):
    MockOverpass.return_value = mock_overpass_api
    results = find_nearby_water_sources(mock_overpass_api, 10.0, 20.0)
    # One from node, one from way
    assert len(results) == 2
    assert results[0]["name"] == "Test Node"
    assert results[1]["name"] == "Test Way"


@patch("overpy.Overpass")
def test_find_nearby_airports(MockOverpass, mock_overpass_api):
    MockOverpass.return_value = mock_overpass_api
    # Add IATA tag for airport test
    mock_overpass_api.query.return_value.nodes[0].tags["iata"] = "TST"
    results = find_nearby_airports(mock_overpass_api, 10.0, 20.0)
    assert len(results) == 2  # Node + Way
    assert results[0]["name"] == "Test Node"
    assert results[0]["iata"] == "TST"
    assert results[1]["name"] == "Test Way"


@patch("overpy.Overpass")
def test_find_nearby_ports(MockOverpass, mock_overpass_api):
    MockOverpass.return_value = mock_overpass_api
    results = find_nearby_ports(mock_overpass_api, 10.0, 20.0)
    assert len(results) == 2  # Node + Way
    assert results[0]["name"] == "Test Node"
    assert results[1]["name"] == "Test Way"


@patch("requests.get")
def test_find_nearby_cell_towers(mock_get):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "cells": [
            {
                "mcc": 250,
                "mnc": 1,
                "lac": 123,
                "cellid": 456,
                "lat": 10.0,
                "lon": 20.0,
            }
        ]
    }
    mock_get.return_value = mock_response
    with patch.dict("os.environ", {"OPENCELLID_API_KEY": "test_key"}):
        results = find_nearby_cell_towers(10.0, 20.0)
        assert len(results) == 1
        assert results[0]["mcc"] == 250


@patch("requests.get")
def test_find_nearby_cell_towers_no_key(mock_get):
    with patch.dict("os.environ", {}, clear=True):
        results = find_nearby_cell_towers(10.0, 20.0)
        assert results == []
        mock_get.assert_not_called()


@patch("overpy.Overpass")
@patch("requests.get")
def test_infrastructure_dependency_command(
    mock_requests_get, MockOverpass, mock_geolocator, mock_overpass_api
):
    """
    Tests the main 'analyze' command integrates all functions.
    """
    MockOverpass.return_value = mock_overpass_api
    # Mock OpenCelliD
    mock_cell_response = MagicMock()
    mock_cell_response.json.return_value = {"cells": []}
    mock_requests_get.return_value = mock_cell_response
    with patch.dict("os.environ", {"OPENCELLID_API_KEY": "test_key"}):
        result = runner.invoke(
            infrastructure_intel_app, ["analyze", "1600 Amphitheatre Parkway"]
        )
    assert result.exit_code == 0
    assert "Coordinates found: Latitude=40.7128, Longitude=-74.0060" in result.stdout
    assert "Nearby Electrical Substations" in result.stdout
    assert "Test Node" in result.stdout
    assert "Nearby Water Sources" in result.stdout
    assert "Nearby Airports" in result.stdout
    assert "Nearby Ports/Harbours" in result.stdout
