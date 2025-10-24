import pytest
from typer.testing import CliRunner
from scapy.all import wrpcap, RadioTap, Dot11, Dot11Beacon, Dot11Elt
from unittest.mock import patch

# The application instance to be tested
from chimera_intel.core.wifi_analyzer import wifi_analyzer_app

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
    )

    # Assert
    assert result.exit_code == 1
    
    # --- FIX: Check for parts of the message to avoid newline/formatting issues ---
    assert "Capture file not found at" in result.stdout
    assert str(non_existent_file) in result.stdout