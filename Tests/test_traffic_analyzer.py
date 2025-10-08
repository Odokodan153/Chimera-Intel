import unittest
from unittest.mock import patch, MagicMock, mock_open
from typer.testing import CliRunner
from scapy.all import IP, TCP, Raw

from chimera_intel.core.traffic_analyzer import (
    carve_files_from_pcap,
    analyze_protocols,
    traffic_analyzer_app,
)

runner = CliRunner()


def create_mock_packets():
    """Helper function to create mock scapy packets for testing."""
    pkt1 = IP(src="192.168.1.1", dst="8.8.8.8") / TCP()
    pkt2 = IP(src="8.8.8.8", dst="192.168.1.1") / TCP()
    pkt3 = IP(src="192.168.1.2", dst="8.8.8.8") / TCP()
    # Add a packet with a raw payload for file carving

    pkt4 = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(dport=80)
        / Raw(load=b"HTTP/1.1 200 OK\r\n\r\n<html>test</html>")
    )
    return [pkt1, pkt2, pkt3, pkt4]


class TestTrafficAnalyzer(unittest.TestCase):
    """Test cases for the Advanced Network Traffic Analysis module."""

    # --- Function Tests ---

    @patch("chimera_intel.core.traffic_analyzer.rdpcap")
    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open)
    @patch("os.makedirs")
    def test_carve_files_from_pcap_success(
        self, mock_makedirs, mock_file, mock_exists, mock_rdpcap
    ):
        """Tests successful file carving from a PCAP."""
        # Arrange

        mock_packets = create_mock_packets()
        # Scapy's sessions() returns a dictionary-like object

        mock_rdpcap.return_value = MagicMock()
        mock_rdpcap.return_value.sessions.return_value = {"session1": mock_packets}

        # Act

        carve_files_from_pcap("test.pcap", "output_dir")

        # Assert

        mock_file.assert_called_with("output_dir/carved_file_0.bin", "wb")
        mock_file().write.assert_called_with(b"<html>test</html>")

    @patch("chimera_intel.core.traffic_analyzer.rdpcap")
    @patch("chimera_intel.core.traffic_analyzer.Network")
    def test_analyze_protocols_success(self, mock_network, mock_rdpcap):
        """Tests the protocol and conversation analysis."""
        # Arrange

        mock_rdpcap.return_value = create_mock_packets()
        mock_net_instance = mock_network.return_value

        # Act

        analyze_protocols("test.pcap")

        # Assert
        # Check that the pyvis network was created and saved

        mock_net_instance.from_nx.assert_called_once()
        mock_net_instance.show.assert_called_with("communication_map.html")

    # --- CLI Tests ---

    @patch("chimera_intel.core.traffic_analyzer.analyze_protocols")
    @patch("chimera_intel.core.traffic_analyzer.carve_files_from_pcap")
    @patch("os.path.exists", return_value=True)
    def test_cli_analyze_traffic_with_carving(
        self, mock_exists, mock_carve, mock_analyze
    ):
        """Tests the 'traffic analyze' command with the --carve-files option."""
        # Act

        result = runner.invoke(
            traffic_analyzer_app, ["analyze", "test.pcap", "--carve-files"]
        )

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Analyzing network traffic", result.stdout)
        self.assertIn("Carving files", result.stdout)
        mock_analyze.assert_called_with("test.pcap")
        mock_carve.assert_called_with("test.pcap", "carved_files_output")

    def test_cli_analyze_traffic_file_not_found(self):
        """Tests the CLI command when the input capture file does not exist."""
        result = runner.invoke(traffic_analyzer_app, ["analyze", "nonexistent.pcap"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Capture file not found", result.stdout)


if __name__ == "__main__":
    unittest.main()
