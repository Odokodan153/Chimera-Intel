import pytest
from typer.testing import CliRunner

# The application instance to be tested
from chimera_intel.core.sigint import sigint_app

runner = CliRunner()

@pytest.fixture
def mock_capture_file(mocker, tmp_path):
    """Creates a mock capture file and mocks the pyModeS decoder."""
    capture_path = tmp_path / "test.cu8"
    
    # Create a dummy file, as the content will be mocked
    with open(capture_path, "wb") as f:
        f.write(b"dummy_data")

    # Mock the pyModeS decoding function
    mock_messages = [
        ("8D4840D6202CC371C32CE0576098", 1633104000.0), # Example ADS-B message
    ]
    mocker.patch('pymodes.demod.decode', return_value=mock_messages)
    return str(capture_path)

def test_decode_capture_adsb_success(mock_capture_file):
    """
    Tests the decode-capture command with the 'adsb' protocol.
    """
    result = runner.invoke(
        sigint_app,
        ["decode-capture", mock_capture_file, "--protocol", "adsb"],
    )

    assert result.exit_code == 0
    assert f"Decoding 'ADSB' signals from: {mock_capture_file}" in result.stdout
    assert "Decoded ADS-B Messages" in result.stdout
    assert "ICAO: 4840d6" in result.stdout # ICAO derived from the mock message

def test_decode_capture_unsupported_protocol(mock_capture_file):
    """
    Tests the command with an unsupported protocol.
    """
    result = runner.invoke(
        sigint_app,
        ["decode-capture", mock_capture_file, "--protocol", "ais"],
    )

    assert result.exit_code == 1
    assert "Error: Protocol 'ais' is not currently supported." in result.stdout

def test_decode_capture_file_not_found():
    """
    Tests the command when the capture file does not exist.
    """
    result = runner.invoke(
        sigint_app,
        ["decode-capture", "non_existent.cu8", "--protocol", "adsb"],
    )

    assert result.exit_code == 1
    assert "Error: Capture file not found at 'non_existent.cu8'" in result.stdout