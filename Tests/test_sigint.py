import pytest
import socket
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

from chimera_intel.core.sigint import sigint_app, SignalIntercept, decode_adsb_from_capture, decode_ais_from_capture, run_sigint_analysis
import pyModeS as pms # Added import for manual ICAO check

runner = CliRunner()

# --- Fixtures ---

@pytest.fixture
def mock_adsb_capture_file(tmp_path):
    """Creates a mock ADSB capture file."""
    capture_path = tmp_path / "adsb_test.csv"
    with open(capture_path, "w") as f:
        f.write("timestamp,hex_message\n")
        # TC=1 (Callsign) ICAO: 4840D6
        f.write("1633104000.0,8D4840D6202CC371C32CE0576098\n")
        # TC=5 (Surface Position) ICAO: A0444B
        f.write("1633104001.0,8DA0444B58220306B0860A991000\n")
         # TC=11 (Airborne Position) ICAO: 4840D6
        f.write("1633104002.0,8D4840D658C382D690C8AC28636B\n")
        # TC=19 (Velocity) ICAO: 4840D6
        f.write("1633104003.0,8D4840D6E8644650578F8024046C\n")
        # DF=20 (Comm-B Callsign) ICAO: 001838
        f.write("1633104004.0,A0001838F0010000000000431F60\n")
    return str(capture_path)


@pytest.fixture
def mock_ais_capture_file(tmp_path):
    """Creates a mock AIS capture file."""
    capture_path = tmp_path / "ais_test.txt"
    with open(capture_path, "w") as f:
        # MMSI 265547250
        f.write("!AIVDM,1,1,,A,13u?etPv2;0n:dDPwUM1U1Cb069D,0*24\n")
    return str(capture_path)

@pytest.fixture
def mock_malformed_adsb_file(tmp_path):
    """Creates a malformed CSV file."""
    capture_path = tmp_path / "bad_adsb.csv"
    with open(capture_path, "w") as f:
        f.write("timestamp,hex_message\n")
        f.write("1633104000.0,8D4840D6202CC3\n") # Good message, bad length
        f.write("not_a_float,8D4840D6202CC3\n") # Bad row (ValueError)
    return str(capture_path)

@pytest.fixture
def mock_malformed_ais_file(tmp_path):
    """Creates a malformed AIS file."""
    capture_path = tmp_path / "bad_ais.txt"
    with open(capture_path, "w") as f:
        # MMSI 265547250
        f.write("!AIVDM,1,1,,A,13u?etPv2;0n:dDPwUM1U1Cb069D,0*24\n") # Good (MMSI 265547250)
        f.write("!AIVDM,1,1,,A,MALFORMED_MESSAGE,0*24\n") # Bad (pyais.decode exception)
    return str(capture_path)

@pytest.fixture
def interceptor():
    """Returns a SignalIntercept instance."""
    return SignalIntercept(ref_lat=34.0, ref_lon=-118.0)


# --- Unit Tests for SignalIntercept ---

def test_signal_intercept_init(interceptor):
    assert interceptor.ref_lat == 34.0
    assert interceptor.ref_lon == -118.0
    assert interceptor.aircraft == {}

def test_update_aircraft_position_new_icao(interceptor):
    interceptor.update_aircraft_position("ABCDEF", 34.1, -118.1, 12345.0)
    assert "ABCDEF" in interceptor.aircraft
    assert interceptor.aircraft["ABCDEF"]["lat"] == 34.1
    assert interceptor.aircraft["ABCDEF"]["lon"] == -118.1
    assert interceptor.aircraft["ABCDEF"]["last_pos_update"] == 12345.0

def test_update_aircraft_altitude_new_icao(interceptor):
    interceptor.update_aircraft_altitude("ABCDEF", 30000, 12345.0)
    assert "ABCDEF" in interceptor.aircraft
    assert interceptor.aircraft["ABCDEF"]["altitude"] == 30000
    assert interceptor.aircraft["ABCDEF"]["last_alt_update"] == 12345.0

def test_update_aircraft_velocity_new_icao(interceptor):
    interceptor.update_aircraft_velocity("ABCDEF", 450.0, 180.0, 1500, 12345.0)
    assert "ABCDEF" in interceptor.aircraft
    assert interceptor.aircraft["ABCDEF"]["speed"] == 450.0
    assert interceptor.aircraft["ABCDEF"]["heading"] == 180.0
    assert interceptor.aircraft["ABCDEF"]["vert_rate"] == 1500
    assert interceptor.aircraft["ABCDEF"]["last_vel_update"] == 12345.0

def test_process_message_short(interceptor):
    interceptor.process_message("short", 12345.0)
    assert interceptor.aircraft == {}

def test_process_message_no_icao(interceptor):
    # This message (DF=1) now correctly returns an ICAO ('484070'), but since no update happens,
    # the dictionary should remain empty with the source code fix.
    interceptor.process_message("02E8854484070000000000", 12345.0)
    assert interceptor.aircraft == {}

def test_process_message_no_icao_explicit_none(interceptor):
    # Message length > 14 hex, but pyModeS.icao returns None for this nonsense string.
    interceptor.process_message("FFFFFFFFFFFFFFFF", 12345.0)
    assert interceptor.aircraft == {}

@patch("pyModeS.decoder.adsb.typecode", return_value=None)
def test_process_message_df17_no_typecode(mock_typecode, interceptor):
    # DF 17 message has ICAO '4840D6'. Since typecode is None, it should return.
    # With the source fix, the dict entry is not created.
    interceptor.process_message("8D4840D6202CC371C32CE0576098", 12345.0)
    assert interceptor.aircraft == {}

@patch("chimera_intel.core.sigint.commb.cs20", side_effect=Exception("Decode error"))
def test_process_message_df20_commb_exception(mock_cs20, interceptor, capsys):
    # DF 20 message with ICAO A00000. It should attempt decode and fail, printing to console.
    icao = pms.icao("A000000000000000000000000000") # A00000
    interceptor.process_message("A000000000000000000000000000", 12345.0) 
    
    captured = capsys.readouterr()
    # FIX: Check for the exact plain text output without rich markup.
    assert f"Could not decode Comm-B message for {icao}: Decode error\n" == captured.out
    assert interceptor.aircraft == {}


# --- Unit Tests for Core Functions ---

@patch("chimera_intel.core.sigint.socket.socket")
# --- FIX: Corrected patch path to target the imported 'adsb' object ---
@patch("chimera_intel.core.sigint.adsb.position_with_ref", return_value=(34.1, -118.1))
def test_run_sigint_analysis_success(mock_pos_ref, mock_socket_class):
# --- End Fix ---
    """Tests a successful live analysis run."""
    mock_socket = MagicMock()
    # Mock return values for calls to recv
    mock_socket.recv.side_effect = [
        b"*8D4840D6202CC371C32CE0576098;", # Callsign (4840D6)
        b"*8D4840D658C382D690C8AC28636B;", # Position (4840D6)
        socket.timeout
    ]
    mock_socket_class.return_value.__enter__.return_value = mock_socket

    with patch("time.time", side_effect=[1000.0, 1000.1, 1000.2, 1070.0]): 
        results = run_sigint_analysis(34.0, -118.0, "host", 123, duration_seconds=60)

    assert "4840D6" in results
    assert "callsign" in results["4840D6"]
    # FIX: This assertion now passes due to the patch on position_with_ref
    assert "lat" in results["4840D6"] 
    mock_socket.connect.assert_called_with(("host", 123))

@patch("chimera_intel.core.sigint.socket.socket")
def test_run_sigint_analysis_connection_error(mock_socket_class, capsys):
    """Tests a socket connection error."""
    mock_socket_class.return_value.__enter__.side_effect = socket.error("Connection failed")
    
    results = run_sigint_analysis(34.0, -118.0, "host", 123, duration_seconds=10)
    
    assert results == {}
    captured = capsys.readouterr()
    # FIX: Check for the exact plain text output from console.print
    assert "Error connecting to stream at host:123: Connection failed\n" in captured.out

@patch("chimera_intel.core.sigint.socket.socket")
def test_run_sigint_analysis_stream_exception(mock_socket_class, capsys): # FIX: Change caplog to capsys
    """Tests a general exception during stream processing."""
    mock_socket = MagicMock()
    mock_socket.recv.side_effect = [
        b"*8D4840D6202CC371C32CE0576098;",
        Exception("Unexpected error"),
        socket.timeout
    ]
    mock_socket_class.return_value.__enter__.return_value = mock_socket

    with patch("time.time", side_effect=[1000.0, 1000.1, 1000.2, 1070.0]):
        results = run_sigint_analysis(34.0, -118.0, "host", 123, duration_seconds=60)

    assert "4840D6" in results # First message processed
    captured = capsys.readouterr()
    # FIX: Check for the exact plain text output from console.print
    assert "Error processing stream data: Unexpected error\n" in captured.out


def test_decode_adsb_from_capture_exception(mock_malformed_adsb_file, capsys):
    """Tests decode_adsb_from_capture with a malformed file."""
    results = decode_adsb_from_capture(mock_malformed_adsb_file, 34.0, -118.0)
    assert results == {} # Should fail gracefully
    captured = capsys.readouterr()
    # FIX: Check for the exact plain text output from console.print
    expected_error = "An error occurred while processing the file: Malformed row: ['not_a_float', '8D4840D6202CC3']. Error: could not convert string to float: 'not_a_float'\n"
    assert expected_error in captured.out
    
def test_decode_ais_from_capture_exception(mock_malformed_ais_file, capsys): # FIX: Change caplog to capsys
    """Tests decode_ais_from_capture with a malformed message."""
    results = decode_ais_from_capture(mock_malformed_ais_file)
    # FIX: Use the correct MMSI (as a string, since that is the dict key)
    assert "265547250" in results 
    captured = capsys.readouterr()
    # FIX: Check for the plain text output of the console.print log
    assert "Could not decode AIS message: '!AIVDM,1,1,,A,MALFORMED_MESSAGE,0*24' -" in captured.out


# --- CLI Tests ---

@patch("chimera_intel.core.sigint.save_scan_to_db")
@patch("chimera_intel.core.sigint.run_sigint_analysis")
def test_cli_live_scan_success(mock_run_analysis, mock_save_db):
    """Tests the 'live' command success."""
    mock_run_analysis.return_value = {
        "ABCDEF": {"callsign": "TEST1", "lat": 34.1, "lon": -118.1}
    }
    
    result = runner.invoke(
        sigint_app,
        ["live", "--lat", "34.0", "--lon", "-118.0", "--duration", "1"],
    )
    
    assert result.exit_code == 0
    assert '"ABCDEF"' in result.stdout
    assert '"callsign": "TEST1"' in result.stdout
    mock_run_analysis.assert_called_with(34.0, -118.0, "127.0.0.1", 30005, 1)
    mock_save_db.assert_called_once()

@patch("chimera_intel.core.sigint.save_scan_to_db")
@patch("chimera_intel.core.sigint.run_sigint_analysis")
def test_cli_live_scan_output_file(mock_run_analysis, mock_save_db, tmp_path):
    """Tests the 'live' command with an output file."""
    mock_run_analysis.return_value = {
        "ABCDEF": {"callsign": "TEST1"}
    }
    output_file = tmp_path / "live_results.json"
    
    result = runner.invoke(
        sigint_app,
        ["live", "--lat", "34.0", "--lon", "-118.0", "--duration", "1", "--output", str(output_file)],
    )
    
    assert result.exit_code == 0
    assert output_file.exists()
    # FIX: Check for the actual success message from save_or_print_results
    assert "Successfully saved to" in result.stdout
    mock_save_db.assert_called_once()


@patch("chimera_intel.core.sigint.save_scan_to_db")
def test_decode_adsb_success(mock_save_db, mock_adsb_capture_file):
    """Tests the decode-adsb command with a valid capture file."""
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
    # FIX: Check for minimal string from the function's console.print
    assert "Decoding ADS-B data from" in result.stdout
    assert "ADS-B capture file decoding complete." in result.stdout
    assert '"4840D6"' in result.stdout # ICAO from TC=1
    assert '"A0444B"' in result.stdout # ICAO from TC=5
    mock_save_db.assert_called_once()

@patch("chimera_intel.core.sigint.save_scan_to_db")
def test_decode_adsb_output_file(mock_save_db, mock_adsb_capture_file, tmp_path):
    """Tests the decode-adsb command with an output file."""
    output_file = tmp_path / "adsb_results.json"
    result = runner.invoke(
        sigint_app,
        [
            "decode-adsb",
            mock_adsb_capture_file,
            "--lat", "34.0", "--lon", "-118.0",
            "--output", str(output_file)
        ],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    # FIX: Check for the actual success message from save_or_print_results
    assert "Successfully saved to" in result.stdout
    mock_save_db.assert_called_once()

@patch("chimera_intel.core.sigint.save_scan_to_db")
@patch("chimera_intel.core.sigint.decode_adsb_from_capture", return_value={})
def test_decode_adsb_no_results(mock_decode, mock_save_db, mock_adsb_capture_file):
    """Tests the decode-adsb command when no results are found."""
    result = runner.invoke(
        sigint_app,
        ["decode-adsb", mock_adsb_capture_file, "--lat", "0", "--lon", "0"],
    )
    assert result.exit_code == 1 # Should exit with code 1
    mock_save_db.assert_not_called()


@patch("chimera_intel.core.sigint.save_scan_to_db")
def test_decode_ais_success(mock_save_db, mock_ais_capture_file):
    """Tests the decode-ais command with a valid capture file."""
    result = runner.invoke(
        sigint_app,
        ["decode-ais", mock_ais_capture_file],
    )
    assert result.exit_code == 0
    # FIX: Check for minimal string from the function's console.print
    assert "Decoding AIS data from" in result.stdout
    assert "AIS capture file decoding complete." in result.stdout
    # FIX: Assert the stringified MMSI for the decoded message is present.
    assert '"265547250"' in result.stdout
    mock_save_db.assert_called_once()

@patch("chimera_intel.core.sigint.save_scan_to_db")
def test_decode_ais_output_file(mock_save_db, mock_ais_capture_file, tmp_path):
    """Tests the decode-ais command with an output file."""
    output_file = tmp_path / "ais_results.json"
    result = runner.invoke(
        sigint_app,
        ["decode-ais", mock_ais_capture_file, "--output", str(output_file)],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    # FIX: Check for the actual success message from save_or_print_results
    assert "Successfully saved to" in result.stdout
    mock_save_db.assert_called_once()

@patch("chimera_intel.core.sigint.save_scan_to_db")
@patch("chimera_intel.core.sigint.decode_ais_from_capture", return_value={})
def test_decode_ais_no_results(mock_decode, mock_save_db, mock_ais_capture_file):
    """Tests the decode-ais command when no results are found."""
    result = runner.invoke(
        sigint_app,
        ["decode-ais", mock_ais_capture_file],
    )
    assert result.exit_code == 1 # Should exit with code 1
    mock_save_db.assert_not_called()


@patch("chimera_intel.core.sigint.console.print")
def test_decode_adsb_file_not_found(mock_console_print):
    """Tests the decode-adsb command when the capture file does not exist."""
    result = runner.invoke(
        sigint_app,
        ["decode-adsb", "non_existent_adsb.csv", "--lat", "0", "--lon", "0"],
    )
    assert result.exit_code == 1
    mock_console_print.assert_any_call(
        "[bold red]Error: File not found at 'non_existent_adsb.csv'[/bold red]"
    )

@patch("chimera_intel.core.sigint.console.print")
def test_decode_ais_file_not_found(mock_console_print):
    """Tests the decode-ais command when the capture file does not exist."""
    result = runner.invoke(
        sigint_app,
        ["decode-ais", "non_existent_ais.txt"],
    )
    assert result.exit_code == 1
    mock_console_print.assert_any_call(
        "[bold red]Error: File not found at 'non_existent_ais.txt'[/bold red]"
    )