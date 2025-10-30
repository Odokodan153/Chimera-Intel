import pytest
from unittest.mock import patch, mock_open
from typer.testing import CliRunner
from scapy.all import IP, TCP, Raw, PacketList

# ---: Import the MAIN app and the app to be tested ---

from chimera_intel.cli import app as main_app
from chimera_intel.core.traffic_analyzer import (
    carve_files_from_pcap,
    analyze_protocols,
    traffic_analyzer_app,
)

# ---: Manually register the app as a plugin ---

main_app.add_typer(traffic_analyzer_app, name="traffic")

runner = CliRunner()


@pytest.fixture
def mock_packets():
    """Helper fixture to create mock scapy packets for testing."""
    pkt1 = IP(src="192.168.1.1", dst="8.8.8.8") / TCP()
    pkt2 = IP(src="8.8.8.8", dst="192.168.1.1") / TCP()
    pkt3 = IP(src="192.168.1.2", dst="8.8.8.8") / TCP()
    # Add a packet with a raw payload for file carving

    pkt4 = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(dport=80)
        / Raw(load=b"HTTP/1.1 200 OK\r\n\r\n<html>test</html>")
    )
    mock_packet_list = PacketList([pkt1, pkt2, pkt3, pkt4])
    mock_packet_list.sessions = lambda: {"mock_session": [pkt1, pkt2, pkt3, pkt4]}
    return mock_packet_list


# --- Function Tests ---

# ---: Patch os.path.exists WHERE IT IS USED ---


@patch("chimera_intel.core.traffic_analyzer.rdpcap")
@patch("builtins.open", new_callable=mock_open)
@patch("os.makedirs")
def test_carve_files_from_pcap_success(
    mock_makedirs, mock_file, mock_rdpcap, mock_packets
):
    """Tests successful file carving from a PCAP."""
    mock_rdpcap.return_value = mock_packets

    carve_files_from_pcap("test.pcap", "output_dir")

    mock_makedirs.assert_called_with("output_dir")
    mock_file.assert_called_with("output_dir/carved_file_0.bin", "wb")
    mock_file().write.assert_called_with(b"<html>test</html>")


@patch("chimera_intel.core.traffic_analyzer.rdpcap")
@patch("chimera_intel.core.traffic_analyzer.Network")
def test_analyze_protocols_success(mock_network, mock_rdpcap, mock_packets):
    """Tests the protocol and conversation analysis."""
    mock_rdpcap.return_value = mock_packets
    mock_net_instance = mock_network.return_value

    analyze_protocols("test.pcap")

    # Check that the pyvis network was created and saved

    mock_net_instance.from_nx.assert_called_once()
    mock_net_instance.save_graph.assert_called_with("communication_map.html")


# --- CLI Tests ---


@patch("chimera_intel.core.traffic_analyzer.analyze_protocols")
@patch("chimera_intel.core.traffic_analyzer.carve_files_from_pcap")
@patch("chimera_intel.core.traffic_analyzer.os.path.exists", return_value=True)
def test_cli_analyze_traffic_with_carving(
    mock_exists, mock_carve, mock_analyze, mocker
):
    """Tests the 'traffic analyze' command with the --carve-files option."""
    mock_console_print = mocker.patch(
        "chimera_intel.core.traffic_analyzer.console.print"
    )

    # ---: Invoke the main_app with the full command ---

    result = runner.invoke(
        main_app, ["traffic", "analyze", "test.pcap", "--carve-files"]
    )

    assert result.exit_code == 0
    mock_console_print.assert_any_call("Analyzing network traffic from: test.pcap")
    mock_console_print.assert_any_call(
        "\nCarving files to directory: carved_files_output"
    )
    mock_analyze.assert_called_with("test.pcap")
    mock_carve.assert_called_with("test.pcap", "carved_files_output")


@patch("chimera_intel.core.traffic_analyzer.os.path.exists", return_value=False)
def test_cli_analyze_traffic_file_not_found(mock_exists, mocker):
    """Tests the CLI command when the input capture file does not exist."""
    mock_console_print = mocker.patch(
        "chimera_intel.core.traffic_analyzer.console.print"
    )

    # ---: Invoke the main_app with the full command ---

    result = runner.invoke(main_app, ["traffic", "analyze", "nonexistent.pcap"])

    assert result.exit_code == 1
    mock_console_print.assert_any_call(
        "Error: Capture file not found at 'nonexistent.pcap'"
    )
