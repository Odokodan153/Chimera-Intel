import pytest
from typer.testing import CliRunner
from unittest.mock import MagicMock
import typer  # Import the main Typer library

# The application instance to be tested
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
