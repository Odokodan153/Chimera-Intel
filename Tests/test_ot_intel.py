from typer.testing import CliRunner
import shodan

# The application instance to be tested
from chimera_intel.core.ot_intel import ot_intel_app

# FIX: Import the API_KEYS object to patch its attribute
from chimera_intel.core.config_loader import API_KEYS

runner = CliRunner()


def test_ot_recon_success(mocker):
    """
    Tests the ot-recon command with a successful Shodan API response.
    """
    # FIX: Patch the API key attribute using patch.object
    mocker.patch.object(API_KEYS, "shodan_api_key", "fake_shodan_key")

    # FIX: Inline the fixture logic
    mock_api_instance = mocker.MagicMock()
    mock_api_instance.host.return_value = {
        "ip_str": "192.168.1.1",
        "org": "Test Industrial Inc.",
        "city": "Cyberville",
        "country_name": "Techland",
        "ports": [502, 20000],
        "data": [{"port": 502, "data": "Modbus Device", "product": "Modicon PLC"}],
    }
    mocker.patch("shodan.Shodan", return_value=mock_api_instance)

    # --- FIX: Invoke *without* the "recon" command name ---
    result = runner.invoke(ot_intel_app, ["--ip-address", "192.168.1.1"])
    # --- END FIX ---

    assert result.exit_code == 0, result.output
    assert "Performing OT reconnaissance on: 192.168.1.1" in result.output
    assert "Organization: Test Industrial Inc." in result.output
    assert "Open Ports: 502, 20000" in result.output
    assert "Identified potential ICS/SCADA protocols" in result.output
    assert "- MODBUS" in result.output


def test_ot_recon_no_api_key(mocker):
    """
    Tests the ot-recon command when the Shodan API key is missing.
    """
    # FIX: Patch the API key to None using patch.object
    mocker.patch.object(API_KEYS, "shodan_api_key", None)

    # --- FIX: Invoke *without* the "recon" command name ---
    result = runner.invoke(ot_intel_app, ["--ip-address", "192.168.1.1"])
    # --- END FIX ---

    assert result.exit_code == 1, result.output
    assert "Error: SHODAN_API_KEY not found in .env file." in result.output


def test_ot_recon_shodan_api_error(mocker):
    """
    Tests the ot-recon command when the Shodan API returns an error.
    """
    # FIX: Patch the API key using patch.object
    mocker.patch.object(API_KEYS, "shodan_api_key", "fake_shodan_key")

    # FIX: Inline the mock setup and configure the side effect
    mock_api_instance = mocker.MagicMock()
    mock_api_instance.host.side_effect = shodan.APIError("Invalid API key.")
    mocker.patch("shodan.Shodan", return_value=mock_api_instance)

    # --- FIX: Invoke *without* the "recon" command name ---
    result = runner.invoke(ot_intel_app, ["--ip-address", "192.168.1.1"])
    # --- END FIX ---

    assert result.exit_code == 1, result.output
    # Match the exact error output from the command
    assert "Error: Invalid API key." in result.output
