import pytest
from typer.testing import CliRunner

# The application instance to be tested

from chimera_intel.core.sigint import sigint_app

runner = CliRunner()


@pytest.fixture
def mock_adsb_capture_file(tmp_path):
    """Creates a mock ADSB capture file."""
    capture_path = tmp_path / "adsb_test.csv"
    with open(capture_path, "w") as f:
        # Add a header and a sample ADS-B message

        f.write("timestamp,hex_message\n")
        f.write("1633104000.0,8D4840D6202CC371C32CE0576098\n")
    return str(capture_path)


@pytest.fixture
def mock_ais_capture_file(tmp_path):
    """Creates a mock AIS capture file."""
    capture_path = tmp_path / "ais_test.txt"
    with open(capture_path, "w") as f:
        # Add a sample AIS message

        f.write("!AIVDM,1,1,,A,13u?etPv2;0n:dDPwUM1U1Cb069D,0*24\n")
    return str(capture_path)


def test_decode_adsb_success(mock_adsb_capture_file):
    """
    Tests the decode-adsb command with a valid capture file.
    """
    result = runner.invoke(
        sigint_app,
        [
            "decode-adsb",
            mock_adsb_capture_file,
            "--lat",
            "34.0522",
            "--lon",
            "-118.2437",
        ],
    )

    assert result.exit_code == 0
    assert f"Decoding ADS-B data from {mock_adsb_capture_file}" in result.stdout
    assert "ADS-B capture file decoding complete." in result.stdout
    # Check for a known ICAO from the sample data

    assert "4840d6" in result.stdout


def test_decode_ais_success(mock_ais_capture_file):
    """
    Tests the decode-ais command with a valid capture file.
    """
    result = runner.invoke(
        sigint_app,
        ["decode-ais", mock_ais_capture_file],
    )

    assert result.exit_code == 0
    assert f"Decoding AIS data from {mock_ais_capture_file}" in result.stdout
    assert "AIS capture file decoding complete." in result.stdout


def test_decode_adsb_file_not_found():
    """
    Tests the decode-adsb command when the capture file does not exist.
    """
    result = runner.invoke(
        sigint_app,
        ["decode-adsb", "non_existent_adsb.csv", "--lat", "0", "--lon", "0"],
    )

    # Typer/Click can return different non-zero exit codes for errors

    assert result.exit_code != 0
    assert "Error: File not found at 'non_existent_adsb.csv'" in result.stdout


def test_decode_ais_file_not_found():
    """
    Tests the decode-ais command when the capture file does not exist.
    """
    result = runner.invoke(
        sigint_app,
        ["decode-ais", "non_existent_ais.txt"],
    )
    assert result.exit_code != 0
    assert "Error: File not found at 'non_existent_ais.txt'" in result.stdout
