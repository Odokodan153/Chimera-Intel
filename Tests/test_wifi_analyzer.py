import pytest
from typer.testing import CliRunner
from scapy.all import wrpcap, RadioTap, Dot11, Dot11Beacon, Dot11Elt
from unittest.mock import patch, MagicMock

# The application instance to be tested
from chimera_intel.core.wifi_analyzer import wifi_analyzer_app, analyze_wifi_capture

# --- FIX: Initialize with mix_stderr=True ---
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


@patch("chimera_intel.core.wifi_analyzer.analyze_wifi_capture")
@patch("os.path.exists", return_value=True)
def test_analyze_wifi_success(mock_exists, mock_analyze_capture, tmp_path):
    """
    Tests the analyze-wifi command with a successful analysis.
    """
    # Arrange: Create a dummy file at the temp path.
    # The content doesn't matter since analyze_wifi_capture is mocked.
    pcap_path = tmp_path / "wifi_test.pcap"
    pcap_path.write_text("dummy pcap content")
    
    # Act
    # --- FIX: Removed "analyze" from the args list ---
    # Since wifi_analyzer_app has only one command, invoke it directly.
    result = runner.invoke(
        wifi_analyzer_app,
        [str(pcap_path)],
        env={"COLUMNS": "120"},
    )

    # Assert
    assert result.exit_code == 0
    mock_analyze_capture.assert_called_once_with(str(pcap_path))


def test_analyze_wifi_file_not_found(tmp_path):
    """
    Tests the command when the capture file does not exist.
    """
    # Arrange: Get a path to a file that is guaranteed not to exist
    non_existent_file = tmp_path / "non_existent.pcapng"

    # Act: No need to patch os.path.exists, the app's internal
    # check will handle this.
    # --- FIX: Removed "analyze" from the args list ---
    result = runner.invoke(
        wifi_analyzer_app,
        [str(non_existent_file)],
        env={"COLUMNS": "120"},
    )

    # Assert
    assert result.exit_code == 1
    
    # --- FIX: Check for parts of the message to avoid newline/formatting issues ---
    assert "Capture file not found at" in result.stdout
    assert str(non_existent_file) in result.stdout

    # --- Tests for analyze_wifi_capture (Logic) ---

    @patch("src.chimera_intel.core.wifi_analyzer.rdpcap")
    def test_analyze_wifi_no_beacons(mock_rdpcap, capsys):
        """Test analysis when the PCAP has no beacon frames."""
        mock_pkt = MagicMock()
        mock_pkt.haslayer.return_value = False  # Not a beacon
        mock_rdpcap.return_value = [mock_pkt]

        analyze_wifi_capture("dummy.pcap")
        captured = capsys.readouterr()
        assert "No Wi-Fi access points found" in captured.out


    @patch("src.chimera_intel.core.wifi_analyzer.rdpcap")
    def test_analyze_wifi_ssid_decode_error(mock_rdpcap, mock_scapy_packet, capsys):
        """Test analysis when an SSID has a UnicodeDecodeError."""
        mock_pkt, stats = mock_scapy_packet
        # Simulate bad encoding
        mock_pkt[MagicMock].info = b"\xff\xfe"
        mock_pkt[MagicMock].info.decode.side_effect = UnicodeDecodeError("utf-8", b"", 0, 1, "reason")
        mock_pkt[MagicMock].info.hex.return_value = "fffe" # Fallback hex value

        mock_rdpcap.return_value = [mock_pkt]
        
        analyze_wifi_capture("dummy.pcap")
        captured = capsys.readouterr()
        
        assert "SSID: fffe" in captured.out
        assert "Security: [green]Open[/green]" in captured.out


    @patch("src.chimera_intel.core.wifi_analyzer.rdpcap")
    @pytest.mark.parametrize("crypto_set, expected_security", [
        ({"WPA2", "WPA"}, "[yellow]WPA/WPA2[/yellow]"),
        ({"WPA2"}, "[green]WPA2[/green]"),
        ({"WPA"}, "[yellow]WPA[/yellow]"),
        ({"WEP"}, "[red]WEP[/red]"),
        (set(), "[green]Open[/green]"), # 'Open' is green in the logic, so we test that
    ])
    def test_analyze_wifi_security_types(mock_rdpcap, mock_scapy_packet, capsys, crypto_set, expected_security):
        """Test detection of various security protocols."""
        mock_pkt, stats = mock_scapy_packet
        stats["crypto"] = crypto_set
        mock_rdpcap.return_value = [mock_pkt]

        analyze_wifi_capture("dummy.pcap")
        captured = capsys.readouterr()
        
        assert f"Security: {expected_security}" in captured.out


    # --- Tests for analyze (CLI Command) ---

    @patch("src.chimera_intel.core.wifi_analyzer.os.path.exists")
    def test_cli_analyze_file_not_found(mock_exists):
        """Test CLI 'analyze' command when the file does not exist."""
        mock_exists.return_value = False
        result = runner.invoke(wifi_analyzer_app, ["analyze", "nonexistent.pcap"])
        
        assert result.exit_code == 1
        assert "Error: Capture file not found" in result.stdout


    @patch("src.chimera_intel.core.wifi_analyzer.os.path.exists")
    @patch("src.chimera_intel.core.wifi_analyzer.analyze_wifi_capture")
    def test_cli_analyze_generic_exception(mock_analyze_logic, mock_exists):
        """Test CLI 'analyze' command when the logic function raises an exception."""
        mock_exists.return_value = True
        mock_analyze_logic.side_effect = Exception("Scapy read error")
        
        result = runner.invoke(wifi_analyzer_app, ["analyze", "broken.pcap"])
        
        assert result.exit_code == 1
        assert "An error occurred during Wi-Fi analysis" in result.stdout
        assert "Scapy read error" in result.stdout


    @patch("src.chimera_intel.core.wifi_analyzer.os.path.exists")
    @patch("src.chimera_intel.core.wifi_analyzer.analyze_wifi_capture")
    def test_cli_analyze_success(mock_analyze_logic, mock_exists):
        """Test a successful run of the CLI 'analyze' command."""
        mock_exists.return_value = True
        
        result = runner.invoke(wifi_analyzer_app, ["analyze", "good.pcap"])
        
        assert result.exit_code == 0
        assert "Analyzing wireless networks from: good.pcap" in result.stdout
        assert "Wireless network analysis complete" in result.stdout
        mock_analyze_logic.assert_called_with("good.pcap")