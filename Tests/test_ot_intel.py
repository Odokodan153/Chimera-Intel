from typer.testing import CliRunner
import shodan

# The application instance to be tested
from chimera_intel.core.ot_intel import ot_intel_app

runner = CliRunner()


def test_ot_recon_success(mocker):
    """
    Tests the ot-recon command with a successful Shodan API response.
    """
    # FIX: Patch the API key using patch.dict *before* invoke
    mocker.patch.dict(
        "chimera_intel.core.ot_intel.API_KEYS", {"shodan_api_key": "fake_shodan_key"}
    )

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

    # Invoke with positional argument
    result = runner.invoke(ot_intel_app, ["recon", "192.168.1.1"])

    assert result.exit_code == 0
    assert "Performing OT reconnaissance on: 192.168.1.1" in result.output
    assert "Organization: Test Industrial Inc." in result.output
    assert "Open Ports: 502, 20000" in result.output
    assert "Identified potential ICS/SCADA protocols" in result.output
    assert "- MODBUS" in result.output


def test_ot_recon_no_api_key(mocker):
    """
    Tests the ot-recon command when the Shodan API key is missing.
    """
    # FIX: Patch the API key to None using patch.dict
    mocker.patch.dict("chimera_intel.core.ot_intel.API_KEYS", {"shodan_api_key": None})

    # Invoke with positional argument
    result = runner.invoke(ot_intel_app, ["recon", "192.168.1.1"])

    assert result.exit_code == 1
    assert "Error: SHODAN_API_KEY not found in .env file." in result.output


def test_ot_recon_shodan_api_error(mocker):
    """
    Tests the ot-recon command when the Shodan API returns an error.
    """
    # FIX: Patch the API key using patch.dict
    mocker.patch.dict(
        "chimera_intel.core.ot_intel.API_KEYS", {"shodan_api_key": "fake_shodan_key"}
    )

    # FIX: Inline the mock setup and configure the side effect
    mock_api_instance = mocker.MagicMock()
    mock_api_instance.host.side_effect = shodan.APIError("Invalid API key.")
    mocker.patch("shodan.Shodan", return_value=mock_api_instance)

    # Invoke with positional argument
    result = runner.invoke(ot_intel_app, ["recon", "192.168.1.1"])

    assert result.exit_code == 1
    # Match the exact error output from the command
    assert "Error: Invalid API key." in result.output