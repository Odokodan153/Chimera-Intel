import pytest
from typer.testing import CliRunner
from scapy.all import wrpcap, RadioTap, Dot11, Dot11Beacon, Dot11Elt
from unittest.mock import patch, MagicMock

# The application instance to be tested
# --- FIX: Ensure imports point to the correct module paths ---
# (Assuming 'chimera_intel.core...' is correct based on original file)
from chimera_intel.core.wifi_analyzer import wifi_analyzer_app, analyze_wifi_capture

# Initialize with mix_stderr=False (default) or True if you need to capture stderr separately
runner = CliRunner()


@pytest.fixture
def mock_wifi_pcap(tmp_path):
    """Creates a mock PCAP file with Wi-Fi beacon frames."""
    pcap_path = tmp_path / "wifi_test.pcap"

    # Create a beacon frame for an open network
    open_net = (
        RadioTap()
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="00:11:22:33:44:55",
            addr3="00:11:22:33:44:55",
        )
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID="SSID", info="OpenWiFi")
    )

    # Create a beacon frame for a WPA2 network
    wpa2_net = (
        RadioTap()
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="aa:bb:cc:dd:ee:ff",
            addr3="aa:bb:cc:dd:ee:ff",
        )
        / Dot11Beacon(cap="ESS+privacy")
        / Dot11Elt(ID="SSID", info="SecureWiFi")
        / Dot11Elt(
            ID="RSNinfo",
            info=(
                b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x80\x00"
            ),
        )
    )

    wrpcap(str(pcap_path), [open_net, wpa2_net])
    return str(pcap_path)


# --- NEW FIX: Add the missing 'mock_scapy_packet' fixture ---
@pytest.fixture
def mock_scapy_packet():
    """Mocks a Scapy packet and its corresponding stats dictionary."""
    # Mock the packet structure
    mock_pkt = MagicMock(spec=Dot11)
    
    # Mock layer access (e.g., packet[Dot11Elt].info)
    mock_elt = MagicMock()
    
    # --- FIX: Mock the .info attribute itself to allow .decode to be mocked ---
    mock_info = MagicMock(spec=bytes)
    mock_info.decode.return_value = "MockSSID"
    mock_elt.info = mock_info
    # --- End Fix ---
    
    # Mock BSSID
    mock_dot11 = MagicMock()
    mock_dot11.addr2 = "00:11:22:33:44:55"
    
    # Mock network_stats()
    mock_beacon = MagicMock()
    stats = {
        "crypto": set(),
        "channel": 1
    }
    mock_beacon.network_stats.return_value = stats

    # Configure the main mock packet
    mock_pkt.haslayer.return_value = True
    mock_pkt.__getitem__.side_effect = lambda layer: {
        Dot11: mock_dot11,
        Dot11Beacon: mock_beacon,
        Dot11Elt: mock_elt
    }[layer]

    return mock_pkt, stats


@patch("chimera_intel.core.wifi_analyzer.analyze_wifi_capture")
@patch("os.path.exists", return_value=True)
def test_analyze_wifi_success(mock_exists, mock_analyze_capture, tmp_path):
    """
    Tests the analyze-wifi command with a successful analysis.
    """
    pcap_path = tmp_path / "wifi_test.pcap"
    pcap_path.write_text("dummy pcap content")
    
    # --- FIX: Corrected CLI invocation to use the 'analyze' subcommand ---
    result = runner.invoke(
        wifi_analyzer_app,
        ["analyze", str(pcap_path)],
        env={"COLUMNS": "120"},
    )

    # Assert
    assert result.exit_code == 0
    mock_analyze_capture.assert_called_once_with(str(pcap_path))


def test_analyze_wifi_file_not_found(tmp_path):
    """
    Tests the command when the capture file does not exist.
    """
    non_existent_file = tmp_path / "non_existent.pcapng"

    # --- FIX: Corrected CLI invocation to use the 'analyze' subcommand ---
    result = runner.invoke(
        wifi_analyzer_app,
        ["analyze", str(non_existent_file)],
        env={"COLUMNS": "120"},
    )

    # Assert
    assert result.exit_code == 1
    assert "Error: Capture file not found" in result.stdout
    assert str(non_existent_file) in result.stdout

# --- Tests for analyze_wifi_capture (Logic) ---

# --- NEW TEST: Test the logic function with the real pcap fixture ---
def test_analyze_wifi_capture_integration(mock_wifi_pcap, capsys):
    """
    Tests the analyze_wifi_capture logic function using the mock pcap file.
    This is an integration test for the logic parsing.
    """
    analyze_wifi_capture(mock_wifi_pcap)
    captured = capsys.readouterr()
    
    # Check for Open network
    assert "SSID: OpenWiFi" in captured.out
    assert "BSSID: 00:11:22:33:44:55" in captured.out
    # --- FIX: Assert plain text, not rich markup ---
    assert "Security: Open" in captured.out

    # Check for WPA2 network
    assert "SSID: SecureWiFi" in captured.out
    assert "BSSID: aa:bb:cc:dd:ee:ff" in captured.out
    # --- FIX: Assert plain text, not rich markup ---
    assert "Security: WPA2" in captured.out


@patch("chimera_intel.core.wifi_analyzer.rdpcap")
def test_analyze_wifi_no_beacons(mock_rdpcap, capsys):
    """Test analysis when the PCAP has no beacon frames."""
    mock_pkt = MagicMock()
    mock_pkt.haslayer.return_value = False  # Not a beacon
    mock_rdpcap.return_value = [mock_pkt]

    analyze_wifi_capture("dummy.pcap")
    captured = capsys.readouterr()
    assert "No Wi-Fi access points found" in captured.out


# --- NEW TEST: Test logic for handling duplicate BSSIDs ---
@patch("chimera_intel.core.wifi_analyzer.rdpcap")
def test_analyze_wifi_duplicate_bssid(mock_rdpcap, mock_scapy_packet, capsys):
    """Test that duplicate BSSIDs are only processed once."""
    mock_pkt, stats = mock_scapy_packet
    stats["crypto"] = {"WEP"} # Set security to WEP
    
    # Return the same packet twice
    mock_rdpcap.return_value = [mock_pkt, mock_pkt]
    
    analyze_wifi_capture("dummy.pcap")
    captured = capsys.readouterr()

    # Ensure the SSID and security type are only printed once
    assert captured.out.count("SSID: MockSSID") == 1
    # --- FIX: Assert plain text, not rich markup ---
    assert captured.out.count("Security: WEP") == 1


# --- FIX: Corrected patch path for rdpcap (was 'src.chimera_intel...') ---
@patch("chimera_intel.core.wifi_analyzer.rdpcap")
def test_analyze_wifi_ssid_decode_error(mock_rdpcap, mock_scapy_packet, capsys):
    """Test analysis when an SSID has a UnicodeDecodeError."""
    mock_pkt, stats = mock_scapy_packet
    
    # Simulate bad encoding
    mock_elt = mock_pkt[Dot11Elt]
    
    # --- FIX: Configure the mock .info attribute, don't replace it ---
    # mock_elt.info = b"\xff\xfe" # Invalid utf-8 <-- OLD/WRONG
    mock_elt.info.decode.side_effect = UnicodeDecodeError("utf-8", b"", 0, 1, "reason")
    # Provide a hex fallback
    mock_elt.info.hex.return_value = "fffe" 
    # --- End Fix ---

    mock_rdpcap.return_value = [mock_pkt]
    
    analyze_wifi_capture("dummy.pcap")
    captured = capsys.readouterr()
    
    # Logic should fall back to hex representation
    assert "SSID: fffe" in captured.out
    # --- FIX: Assert plain text, not rich markup ---
    assert "Security: Open" in captured.out


# --- FIX: Corrected patch path for rdpcap (was 'src.chimera_intel...') ---
@patch("chimera_intel.core.wifi_analyzer.rdpcap")
# --- FIX: Update expected strings to be plain text ---
@pytest.mark.parametrize("crypto_set, expected_security", [
    ({"WPA2", "WPA"}, "WPA/WPA2"),
    ({"WPA2"}, "WPA2"),
    ({"WPA"}, "WPA"),
    ({"WEP"}, "WEP"),
    (set(), "Open"),
])
def test_analyze_wifi_security_types(mock_rdpcap, mock_scapy_packet, capsys, crypto_set, expected_security):
    """Test detection of various security protocols and their colors."""
    mock_pkt, stats = mock_scapy_packet
    stats["crypto"] = crypto_set
    mock_rdpcap.return_value = [mock_pkt]

    analyze_wifi_capture("dummy.pcap")
    captured = capsys.readouterr()
    
    # --- FIX: Assert plain text, not rich markup ---
    assert f"Security: {expected_security}" in captured.out