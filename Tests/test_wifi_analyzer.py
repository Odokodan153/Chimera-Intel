import pytest
from typer.testing import CliRunner
from scapy.all import wrpcap, RadioTap, Dot11, Dot11Beacon, Dot11Elt
import os

# The application instance to be tested

from chimera_intel.core.wifi_analyzer import wifi_analyzer_app

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


def test_analyze_wifi_success(mock_wifi_pcap):
    """
    Tests the analyze-wifi command with a successful analysis.
    """
    result = runner.invoke(
        wifi_analyzer_app,
        ["analyze", mock_wifi_pcap],
    )

    assert result.exit_code == 0
    assert "Discovered Wi-Fi Networks" in result.stdout
    assert "SSID: OpenWiFi" in result.stdout
    assert "Security: [red]Open[/red]" in result.stdout
    assert "SSID: SecureWiFi" in result.stdout
    assert "Security: [green]WPA2[/green]" in result.stdout


def test_analyze_wifi_file_not_found():
    """
    Tests the command when the capture file does not exist.
    """
    result = runner.invoke(
        wifi_analyzer_app,
        ["analyze", "non_existent.pcapng"],
    )

    assert result.exit_code == 1
    assert "Error: Capture file not found at 'non_existent.pcapng'" in result.stdout
