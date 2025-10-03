import pytest
from typer.testing import CliRunner
import shodan

# The application instance to be tested
from chimera_intel.core.ot_intel import ot_intel_app

runner = CliRunner()

@pytest.fixture
def mock_shodan_api(mocker):
    """Mocks the shodan.Shodan API calls."""
    mock_api_instance = mocker.MagicMock()
    mock_api_instance.host.return_value = {
        "ip_str": "192.168.1.1",
        "org": "Test Industrial Inc.",
        "city": "Cyberville",
        "country_name": "Techland",
        "ports": [502, 20000],
        "data": [
            {
                "port": 502,
                "data": "Modbus Device",
                "product": "Modicon PLC"
            }
        ]
    }
    mocker.patch('shodan.Shodan', return_value=mock_api_instance)
    return mock_api_instance

def test_ot_recon_success(mocker, mock_shodan_api):
    """
    Tests the ot-recon command with a successful Shodan API response.
    """
    mocker.patch('chimera_intel.core.ot_intel.API_KEYS.shodan_api_key', 'fake_shodan_key')

    result = runner.invoke(ot_intel_app, ["recon", "--ip", "192.168.1.1"])

    assert result.exit_code == 0
    assert "Performing OT reconnaissance on: 192.168.1.1" in result.stdout
    assert "Organization: Test Industrial Inc." in result.stdout
    assert "Open Ports: 502, 20000" in result.stdout
    assert "Identified potential ICS/SCADA protocols" in result.stdout
    assert "- MODBUS" in result.stdout

def test_ot_recon_no_api_key(mocker):
    """
    Tests the ot-recon command when the Shodan API key is missing.
    """

    mocker.patch('chimera_intel.core.ot_intel.API_KEYS.shodan_api_key', None)

    result = runner.invoke(ot_intel_app, ["recon", "--ip", "192.168.1.1"])

    assert result.exit_code == 1
    assert "Error: SHODAN_API_KEY not found in .env file." in result.stdout

def test_ot_recon_shodan_api_error(mocker, mock_shodan_api):
    """
    Tests the ot-recon command when the Shodan API returns an error.
    """
    mocker.patch('chimera_intel.core.ot_intel.API_KEYS.shodan_api_key', 'fake_shodan_key')
    mock_shodan_api.host.side_effect = shodan.APIError("Invalid API key.")

    result = runner.invoke(ot_intel_app, ["recon", "--ip", "192.168.1.1"])

    assert result.exit_code == 1
    assert "Shodan API Error: Invalid API key." in result.stdout