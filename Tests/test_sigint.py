import pytest
from typer.testing import CliRunner
from unittest.mock import patch

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


@patch("chimera_intel.core.sigint.save_scan_to_db")
def test_decode_adsb_success(mock_save_db, mock_adsb_capture_file):
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
    # Check for a known ICAO from the sample data (must be uppercase)

    assert '"4840D6"' in result.stdout
    # Ensure database error is not in the output

    assert "Database Error" not in result.stdout
    mock_save_db.assert_called_once()


@patch("chimera_intel.core.sigint.save_scan_to_db")
def test_decode_ais_success(mock_save_db, mock_ais_capture_file):
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
    assert "Database Error" not in result.stdout
    mock_save_db.assert_called_once()


@patch("chimera_intel.core.sigint.console.print")
def test_decode_adsb_file_not_found(mock_console_print):
    """
    Tests the decode-adsb command when the capture file does not exist.
    """
    result = runner.invoke(
        sigint_app,
        ["decode-adsb", "non_existent_adsb.csv", "--lat", "0", "--lon", "0"],
    )

    # The app should exit with code 1 as defined in sigint.py

    assert result.exit_code == 1
    # Check that the rich console was called with the error message

    mock_console_print.assert_any_call(
        "[bold red]Error: File not found at 'non_existent_adsb.csv'[/bold red]"
    )


@patch("chimera_intel.core.sigint.console.print")
def test_decode_ais_file_not_found(mock_console_print):
    """
    Tests the decode-ais command when the capture file does not exist.
    """
    result = runner.invoke(
        sigint_app,
        ["decode-ais", "non_existent_ais.txt"],
    )
    # The app should exit with code 1

    assert result.exit_code == 1
    mock_console_print.assert_any_call(
        "[bold red]Error: File not found at 'non_existent_ais.txt'[/bold red]"
    )
