import pytest
from typer.testing import CliRunner
from scapy.all import TCP, IP, Raw, wrpcap
import os

# The application instance to be tested
from chimera_intel.core.traffic_analyzer import traffic_analyzer_app

runner = CliRunner()

@pytest.fixture
def mock_pcap_file(tmp_path):
    """Creates a mock PCAP file for testing."""
    pcap_path = tmp_path / "test.pcap"
    
    # Create a simple packet with a fake HTTP response
    http_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"This is the file content."
    )
    
    packet = IP(dst="1.2.3.4") / TCP(dport=80) / Raw(load=http_response)
    wrpcap(str(pcap_path), [packet])
    return str(pcap_path)

def test_analyze_traffic_carve_files_success(mock_pcap_file):
    """
    Tests the analyze-traffic command with the --carve-files option.
    """
    result = runner.invoke(
        traffic_analyzer_app,
        ["analyze", mock_pcap_file, "--carve-files"],
    )

    output_dir = "carved_files_output"
    carved_file_path = os.path.join(output_dir, "carved_file_0.bin")

    assert result.exit_code == 0
    assert f"Analyzing network traffic from: {mock_pcap_file}" in result.stdout
    assert f"Carving files to directory: {output_dir}" in result.stdout
    assert f"Carved file: {carved_file_path}" in result.stdout
    
    # Verify the carved file's content
    with open(carved_file_path, "rb") as f:
        content = f.read()
    assert content == b"This is the file content."

    # Clean up the created directory and file
    os.remove(carved_file_path)
    os.rmdir(output_dir)

def test_analyze_traffic_file_not_found():
    """
    Tests the command when the specified capture file does not exist.
    """
    result = runner.invoke(
        traffic_analyzer_app,
        ["analyze", "non_existent_file.pcap"],
    )

    assert result.exit_code == 1
    assert "Error: Capture file not found at 'non_existent_file.pcap'" in result.stdout