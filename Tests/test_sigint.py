import pytest
import socket
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, PropertyMock, AsyncMock
import httpx
from chimera_intel.core.sigint import (
    sigint_app,
    SignalIntercept,
    decode_adsb_from_capture,
    decode_ais_from_capture,
    run_sigint_analysis,
    monitor_rf_spectrum,
)
from chimera_intel.core.schemas import (RFSpectrumAnomaly, RFSpectrumReport)
import pyModeS as pms  # Added import for manual ICAO check

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
        f.write("1633104000.0,8D4840D6202CC3\n")  # Good message, bad length
        f.write("not_a_float,8D4840D6202CC3\n")  # Bad row (ValueError)
    return str(capture_path)


@pytest.fixture
def mock_malformed_ais_file(tmp_path):
    """Creates a malformed AIS file."""
    capture_path = tmp_path / "bad_ais.txt"
    with open(capture_path, "w") as f:
        # MMSI 265547250
        f.write(
            "!AIVDM,1,1,,A,13u?etPv2;0n:dDPwUM1U1Cb069D,0*24\n"
        )  # Good (MMSI 265547250)
        f.write(
            "!AIVDM,1,1,,A,MALFORMED_MESSAGE,0*24\n"
        )  # Bad (pyais.decode exception)
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
    icao = pms.icao("A000000000000000000000000000")  # A00000
    interceptor.process_message("A000000000000000000000000000", 12345.0)

    captured = capsys.readouterr()
    # FIX: Check for the exact plain text output without rich markup.
    assert f"Could not decode Comm-B message for {icao}: Decode error\n" == captured.out
    assert interceptor.aircraft == {}


# --- Unit Tests for Core Functions ---


@patch("chimera_intel.core.sigint.socket.socket")
@patch("chimera_intel.core.sigint.adsb.position_with_ref", return_value=(34.1, -118.1))
# --- START FIX: Swapped mock arguments to match decorator order (bottom-up) ---
def test_run_sigint_analysis_success(mock_pos_ref, mock_socket_class):
    # --- END FIX ---
    """Tests a successful live analysis run."""
    mock_socket = MagicMock()
    # Mock return values for calls to recv
    mock_socket.recv.side_effect = [
        b"*8D4840D6202CC371C32CE0576098;",  # Callsign (4840D6)
        b"*8D4840D658C382D690C8AC28636B;",  # Position (4840D6)
        socket.timeout,
    ]
    mock_socket_class.return_value.__enter__.return_value = mock_socket

    # --- FIX: Added more time ticks to allow the loop to process both messages ---
    with patch(
        "time.time",
        side_effect=[
            1000.0,  # start_time
            1000.1,  # loop 1 check (processes msg 1)
            1000.2,  # process_message timestamp for msg 1
            1000.3,  # loop 2 check (processes msg 2)
            1000.4,  # process_message timestamp for msg 2
            1000.5,  # loop 3 check (hits socket.timeout)
            1070.0,  # loop 4 check (exits)
        ],
    ):
        # --- END FIX ---
        results = run_sigint_analysis(34.0, -118.0, "host", 123, duration_seconds=60)

    assert "4840D6" in results
    assert "callsign" in results["4840D6"]
    # FIX: This assertion now passes due to the patch on position_with_ref
    assert "lat" in results["4840D6"]
    mock_socket.connect.assert_called_with(("host", 123))


@patch("chimera_intel.core.sigint.socket.socket")
def test_run_sigint_analysis_connection_error(mock_socket_class, capsys):
    """Tests a socket connection error."""
    mock_socket_class.return_value.__enter__.side_effect = socket.error(
        "Connection failed"
    )

    results = run_sigint_analysis(34.0, -118.0, "host", 123, duration_seconds=10)

    assert results == {}
    captured = capsys.readouterr()
    # FIX: Check for the exact plain text output from console.print
    assert "Error connecting to stream at host:123: Connection failed\n" in captured.out


@patch("chimera_intel.core.sigint.socket.socket")
def test_run_sigint_analysis_stream_exception(
    mock_socket_class, capsys
):  # FIX: Change caplog to capsys
    """Tests a general exception during stream processing."""
    mock_socket = MagicMock()
    mock_socket.recv.side_effect = [
        b"*8D4840D6202CC371C32CE0576098;",
        Exception("Unexpected error"),
        socket.timeout,
    ]
    mock_socket_class.return_value.__enter__.return_value = mock_socket

    # --- FIX: Add more time.time() ticks to allow the loop to run and hit the exception ---
    with patch(
        "time.time",
        side_effect=[
            1000.0,  # start_time
            1000.1,  # loop 1 check
            1000.2,  # process_message timestamp
            1000.3,  # loop 2 check (hits Exception)
            1000.4,  # loop 3 check (hits socket.timeout)
            1070.0,  # loop 4 check (exits)
        ],
    ):
        results = run_sigint_analysis(34.0, -118.0, "host", 123, duration_seconds=60)
    # --- End Fix ---

    assert "4840D6" in results  # First message processed
    captured = capsys.readouterr()
    # FIX: Check for the exact plain text output from console.print
    assert "Error processing stream data: Unexpected error\n" in captured.out


def test_decode_adsb_from_capture_exception(mock_malformed_adsb_file, capsys):
    """Tests decode_adsb_from_capture with a malformed file."""
    results = decode_adsb_from_capture(mock_malformed_adsb_file, 34.0, -118.0)
    assert results == {}  # Should fail gracefully
    captured = capsys.readouterr()
    # FIX: Check for the exact plain text output from console.print
    # This test now passes because the Console(width=200) in sigint.py
    # prevents the error message from being wrapped with a '\n'.
    expected_error = "An error occurred while processing the file: Malformed row: ['not_a_float', '8D4840D6202CC3']. Error: could not convert string to float: 'not_a_float'\n"
    assert expected_error in captured.out


def test_decode_ais_from_capture_exception(
    mock_malformed_ais_file, capsys
):  # FIX: Change caplog to capsys
    """Tests decode_ais_from_capture with a malformed message."""
    results = decode_ais_from_capture(mock_malformed_ais_file)
    # FIX: Use the correct MMSI (as a string, since that is the dict key)
    assert "265547250" in results
    captured = capsys.readouterr()
    # FIX: Check for the plain text output of the console.print log
    assert (
        "Could not decode AIS message: '!AIVDM,1,1,,A,MALFORMED_MESSAGE,0*24' -"
        in captured.out
    )


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
    mock_run_analysis.return_value = {"ABCDEF": {"callsign": "TEST1"}}
    output_file = tmp_path / "live_results.json"

    result = runner.invoke(
        sigint_app,
        [
            "live",
            "--lat",
            "34.0",
            "--lon",
            "-118.0",
            "--duration",
            "1",
            "--output",
            str(output_file),
        ],
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
    assert '"4840D6"' in result.stdout  # ICAO from TC=1
    assert '"A0444B"' in result.stdout  # ICAO from TC=5
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
            "--lat",
            "34.0",
            "--lon",
            "-118.0",
            "--output",
            str(output_file),
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
    assert result.exit_code == 1  # Should exit with code 1
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
    assert result.exit_code == 1  # Should exit with code 1
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
@patch("chimera_intel.core.sigint.socket.socket")
def test_monitor_rf_spectrum_success(mock_socket_class, capsys):
    """Tests a successful RF spectrum monitoring run with an anomaly."""
    
    mock_socket = MagicMock()
    mock_socket.recv.side_effect = [
        b"1678886400.0,88100000,88300000,-45.0\n",  # Below threshold
        b"1678886401.0,92500000,92700000,-25.5\n",  # Anomaly
        socket.timeout,
    ]
    mock_socket_class.return_value.__enter__.return_value = mock_socket

    threshold = -30.0

    with patch(
        "time.time",
        side_effect=[
            1000.0,  # start_time
            1000.1,  # loop 1 check (processes msg 1)
            1000.3,  # loop 2 check (processes msg 2)
            1000.5,  # loop 3 check (hits socket.timeout)
            1070.0,  # loop 4 check (exits)
        ],
    ):
        results = monitor_rf_spectrum("host", 1234, 60, threshold)

    assert results.total_anomalies_found == 1
    assert results.anomalies[0].power_dbm == -25.5
    assert results.anomalies[0].frequency_mhz == 92.6  # (92500000 + 92700000) / 2 / 1M
    assert results.error is None
    mock_socket.connect.assert_called_with(("host", 1234))


@patch("chimera_intel.core.sigint.socket.socket")
def test_monitor_rf_spectrum_connection_error(mock_socket_class, capsys):
    """Tests an RF spectrum monitor connection error."""
    mock_socket_class.return_value.__enter__.side_effect = socket.error(
        "Connection failed"
    )

    results = monitor_rf_spectrum("host", 1234, 10, -30.0)

    assert results.total_anomalies_found == 0
    assert results.error == "Connection failed"
    captured = capsys.readouterr()
    assert "Error connecting to stream at host:1234: Connection failed" in captured.out


@patch("chimera_intel.core.sigint.socket.socket")
def test_monitor_rf_spectrum_malformed_line(mock_socket_class, capsys):
    """Tests that the spectrum monitor handles malformed stream data."""
    
    mock_socket = MagicMock()
    mock_socket.recv.side_effect = [
        b"1678886400.0,88100000,88300000,-45.0\n",  # Good
        b"not,a,valid,line\n",                     # Malformed
        b"1678886401.0,92500000,92700000,-25.5\n",  # Anomaly
        socket.timeout,
    ]
    mock_socket_class.return_value.__enter__.return_value = mock_socket

    with patch(
        "time.time",
        side_effect=[
            1000.0,  # start_time
            1000.1,  # loop 1
            1000.3,  # loop 2
            1000.5,  # loop 3
            1000.7,  # loop 4
            1070.0,  # loop 5 (exits)
        ],
    ):
        results = monitor_rf_spectrum("host", 1234, 60, -30.0)

    # Should find the one valid anomaly
    assert results.total_anomalies_found == 1
    assert results.anomalies[0].power_dbm == -25.5
    
    # Should log the error
    captured = capsys.readouterr()
    assert "Error parsing spectrum data line: 'not,a,valid,line'" in captured.out


# ... (existing CLI tests for cell-info) ...

@patch("chimera_intel.core.sigint.save_scan_to_db")
@patch("chimera_intel.core.sigint.monitor_rf_spectrum")
def test_cli_monitor_spectrum_success(mock_monitor_spectrum, mock_save_db, capsys):
    """Tests the 'monitor-spectrum' CLI command success."""
    mock_anomaly = RFSpectrumAnomaly(
        timestamp=1678886401.0,
        frequency_mhz=92.6,
        power_dbm=-25.5,
        details="Signal exceeded threshold"
    )
    mock_report = RFSpectrumReport(
        target_host="127.0.0.1",
        port=1234,
        duration_seconds=10,
        anomaly_threshold_dbm=-30.0,
        total_anomalies_found=1,
        anomalies=[mock_anomaly]
    )
    mock_monitor_spectrum.return_value = mock_report

    result = runner.invoke(
        sigint_app,
        ["monitor-spectrum", "--duration", "10", "--threshold", "-30.0"],
    )

    assert result.exit_code == 0
    assert '"total_anomalies_found": 1' in result.stdout
    assert '"frequency_mhz": 92.6' in result.stdout
    mock_monitor_spectrum.assert_called_with("127.0.0.1", 1234, 10, -30.0)
    mock_save_db.assert_called_once()
# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio


@pytest.fixture
def mock_api_keys():
    """Mocks the API_KEYS config object."""
    with patch(
        "chimera_intel.core.sigint.API_KEYS", new_callable=PropertyMock
    ) as mock_keys:
        mock_keys.opencellid_api_key = "test_key_123"
        yield mock_keys


@pytest.fixture
def mock_httpx_client():
    """Mocks the httpx.AsyncClient."""
    with patch("httpx.AsyncClient", autospec=True) as mock_client_class:
        mock_client = mock_client_class.return_value.__aenter__.return_value
        mock_client.get = AsyncMock()
        yield mock_client


async def test_get_cell_tower_info_success(mock_httpx_client):
    """Tests a successful cell tower lookup."""
    from chimera_intel.core.sigint import get_cell_tower_info
    from chimera_intel.core.schemas import CellTowerInfo

    # Mock a successful API response
    mock_response = httpx.Response(
        200,
        json={
            "status": "ok",
            "lat": 48.243,
            "lon": 16.372,
            "mcc": 232,
            "mnc": 1,
            "lac": 10101,
            "cellid": 12345,
            "range": 1000,
            "radio": "GSM",
            "updated": 1678886400,
        },
    )
    mock_httpx_client.get.return_value = mock_response

    result = await get_cell_tower_info(
        mcc=232, mnc=1, lac=10101, cid=12345, api_key="test_key"
    )

    # Validate schema (Pydantic model_validate is used in the function)
    validated = CellTowerInfo.model_validate(mock_response.json()).model_dump()
    assert result == validated
    assert "error" not in result
    assert result["lat"] == 48.243


async def test_get_cell_tower_info_api_error(mock_httpx_client):
    """Tests an API-level error (e.g., cell not found)."""
    from chimera_intel.core.sigint import get_cell_tower_info

    # Mock an API error response
    mock_response = httpx.Response(
        200, json={"status": "error", "error": "No data"}
    )
    mock_httpx_client.get.return_value = mock_response

    result = await get_cell_tower_info(
        mcc=999, mnc=1, lac=1, cid=1, api_key="test_key"
    )

    assert "error" in result
    assert result["error"] == "No data"


async def test_get_cell_tower_info_http_error(mock_httpx_client):
    """Tests an HTTP 500 server error."""
    from chimera_intel.core.sigint import get_cell_tower_info

    # Mock an HTTP error
    mock_httpx_client.get.side_effect = httpx.HTTPStatusError(
        "Server Error", request=MagicMock(), response=httpx.Response(500)
    )

    result = await get_cell_tower_info(
        mcc=232, mnc=1, lac=1, cid=1, api_key="test_key"
    )

    assert "error" in result
    assert "HTTP error" in result["error"]


# --- New CLI Tests for Cellular SIGINT ---


@patch("chimera_intel.core.sigint.save_scan_to_db")
@patch("chimera_intel.core.sigint.asyncio.run")
def test_cli_cell_info_success(
    mock_asyncio_run, mock_save_db, mock_api_keys, capsys
):
    """Tests the 'cell-info' CLI command success."""
    mock_success_data = {
        "status": "ok",
        "lat": 48.243,
        "lon": 16.372,
        "mcc": 232,
        "mnc": 1,
        "lac": 10101,
        "cellid": 12345,
        "range": 1000,
        "radio": "GSM",
        "updated": 1678886400,
    }
    mock_asyncio_run.return_value = mock_success_data

    result = runner.invoke(
        sigint_app,
        ["cell-info", "--mcc", "232", "--mnc", "1", "--lac", "10101", "--cid", "12345"],
    )

    assert result.exit_code == 0
    assert '"lat": 48.243' in result.stdout
    assert "Cell tower lookup complete." in result.stdout
    mock_save_db.assert_called_once_with(
        target="cell:232-1-10101-12345",
        module="sigint_cell_info",
        data=mock_success_data,
    )


@patch("chimera_intel.core.sigint.asyncio.run")
def test_cli_cell_info_no_key(mock_asyncio_run, capsys):
    """Tests the 'cell-info' CLI command when no API key is set."""
    # Mock the API_KEYS object to have no key
    with patch(
        "chimera_intel.core.sigint.API_KEYS", new_callable=PropertyMock
    ) as mock_keys:
        mock_keys.opencellid_api_key = None

        result = runner.invoke(
            sigint_app,
            [
                "cell-info",
                "--mcc",
                "232",
                "--mnc",
                "1",
                "--lac",
                "10101",
                "--cid",
                "12345",
            ],
        )

    assert result.exit_code == 1
    assert "Error: OPENCELLID_API_KEY not found" in result.stdout
    mock_asyncio_run.assert_not_called()


@patch("chimera_intel.core.sigint.save_scan_to_db")
@patch("chimera_intel.core.sigint.asyncio.run")
def test_cli_cell_info_api_fail(
    mock_asyncio_run, mock_save_db, mock_api_keys, capsys
):
    """Tests the 'cell-info' CLI command when the API returns an error."""
    mock_asyncio_run.return_value = {"error": "No data"}

    result = runner.invoke(
        sigint_app,
        ["cell-info", "--mcc", "999", "--mnc", "1", "--lac", "1", "--cid", "1"],
    )

    assert result.exit_code == 1
    assert "Failed to retrieve cell tower data: No data" in result.stdout
    mock_save_db.assert_not_called()
