# Chimera-Intel/Tests/test_masint.py

import pytest
import numpy as np
import cv2
from typer.testing import CliRunner
from unittest.mock import patch
from scapy.all import Ether, IP, TCP, wrpcap

from chimera_intel.core.masint import app as masint_app, Masint, LibrosaPlaceholder

# Check if librosa and soundfile are actually installed for the "installed" tests
try:
    import soundfile as sf

    librosa_installed = True
except ImportError:
    librosa_installed = False

runner = CliRunner()


@pytest.fixture
def masint_instance():
    return Masint()


@pytest.fixture
def mock_pcap_file(tmp_path):
    """Creates a dummy pcap file."""
    pcap_file = tmp_path / "test.pcap"
    packets = [Ether() / IP(dst="8.8.8.8") / TCP() for _ in range(10)]
    wrpcap(str(pcap_file), packets)
    return str(pcap_file)


@pytest.fixture
def mock_empty_pcap_file(tmp_path):
    """Creates an empty pcap file."""
    pcap_file = tmp_path / "empty.pcap"
    wrpcap(str(pcap_file), [])
    return str(pcap_file)


@pytest.fixture
def mock_thermal_image_file(tmp_path):
    """Creates a dummy thermal image."""
    image_file = tmp_path / "thermal.png"
    img = np.zeros((100, 100), dtype=np.uint8)
    cv2.rectangle(img, (20, 20), (40, 40), 255, -1)  # A "hotspot"
    cv2.imwrite(str(image_file), img)
    return str(image_file)


@pytest.fixture
@pytest.mark.skipif(not librosa_installed, reason="librosa or soundfile not installed")
def mock_audio_file(tmp_path):
    """Creates a dummy audio file."""
    audio_file = tmp_path / "test.wav"
    samplerate = 22050
    data = np.random.randn(2 * samplerate)  # 2 seconds of noise
    sf.write(str(audio_file), data, samplerate)
    return str(audio_file)


# --- Unit Tests for Masint Class ---


def test_analyze_rf_pcap_success(masint_instance, mock_pcap_file):
    signature = masint_instance.analyze_rf_pcap(mock_pcap_file)
    assert signature is not None
    assert signature["packet_count"] == 10
    assert len(signature["size_histogram"]) == 10


def test_analyze_rf_pcap_empty(masint_instance, mock_empty_pcap_file, capsys):
    signature = masint_instance.analyze_rf_pcap(mock_empty_pcap_file)
    assert signature is None
    captured = capsys.readouterr()
    # Fix: Check for the exact plain text output, as rich markup is stripped by capsys.
    assert "PCAP file is empty or could not be read.\n" == captured.out


@patch("chimera_intel.core.masint.rdpcap", side_effect=Exception("Scapy error"))
def test_analyze_rf_pcap_exception(mock_rdpcap, masint_instance, capsys):
    signature = masint_instance.analyze_rf_pcap("dummy.pcap")
    assert signature is None
    captured = capsys.readouterr()
    # Fix: Check for the exact plain text output.
    assert "Error processing PCAP file: Scapy error\n" == captured.out


@pytest.mark.skipif(not librosa_installed, reason="librosa or soundfile not installed")
def test_analyze_acoustic_signature_success(masint_instance, mock_audio_file):
    signature = masint_instance.analyze_acoustic_signature(mock_audio_file)
    assert signature is not None
    assert isinstance(signature, list)
    assert len(signature) == 13  # 13 MFCCs


@patch(
    "chimera_intel.core.masint.librosa.load",
    side_effect=Exception("Corrupt audio file"),
)
def test_analyze_acoustic_signature_exception(mock_load, masint_instance, capsys):
    # This test assumes librosa *is* installed (or mocked as such)
    signature = masint_instance.analyze_acoustic_signature("dummy.wav")
    assert signature is None
    captured = capsys.readouterr()
    # Fix: Check for the exact plain text output.
    assert "Error processing audio file: Corrupt audio file\n" == captured.out


@patch("chimera_intel.core.masint.librosa", new_callable=LibrosaPlaceholder)
def test_analyze_acoustic_signature_not_installed(
    mock_librosa_placeholder, masint_instance, capsys
):
    """Tests the case where librosa is not installed."""
    signature = masint_instance.analyze_acoustic_signature("dummy.wav")
    assert signature is None
    captured = capsys.readouterr()
    # This assertion already uses 'in' and is robust enough for the full message.
    assert "librosa library not installed" in captured.out

    # Also test the placeholder itself
    with pytest.raises(ImportError, match="librosa is not installed"):
        mock_librosa_placeholder.load("dummy.wav")


def test_analyze_thermal_image_success(masint_instance, mock_thermal_image_file):
    hotspots = masint_instance.analyze_thermal_image(
        mock_thermal_image_file, threshold=200
    )
    assert hotspots is not None
    assert len(hotspots) == 1
    assert hotspots[0]["x"] == 20
    assert hotspots[0]["width"] == 21  # cv2.boundingRect behavior


@patch("chimera_intel.core.masint.cv2.imread", return_value=None)
def test_analyze_thermal_image_file_not_found(mock_imread, masint_instance, capsys):
    hotspots = masint_instance.analyze_thermal_image("bad.png")
    assert hotspots is None
    captured = capsys.readouterr()
    # Fix: Check for the exact plain text output.
    assert "Could not read image file.\n" == captured.out


@patch("chimera_intel.core.masint.cv2.imread", side_effect=Exception("OpenCV error"))
def test_analyze_thermal_image_exception(mock_imread, masint_instance, capsys):
    hotspots = masint_instance.analyze_thermal_image("bad.png")
    assert hotspots is None
    captured = capsys.readouterr()
    # Fix: Check for the exact plain text output.
    assert "Error processing image file: OpenCV error\n" == captured.out


# --- CLI Tests ---


@patch("chimera_intel.core.masint.Masint.analyze_rf_pcap")
def test_cli_rf_pcap_success(mock_analyze, mock_pcap_file):
    mock_analyze.return_value = {
        "packet_count": 10,
        "size_histogram": [10, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    }
    result = runner.invoke(masint_app, ["rf-pcap", mock_pcap_file])
    assert result.exit_code == 0
    assert "Generated RF Signature" in result.stdout
    assert '"packet_count": 10' in result.stdout


@patch("chimera_intel.core.masint.Masint.analyze_rf_pcap", return_value=None)
def test_cli_rf_pcap_none(mock_analyze, mock_pcap_file):
    result = runner.invoke(masint_app, ["rf-pcap", mock_pcap_file])
    assert result.exit_code == 0
    assert "Generated RF Signature" not in result.stdout  # No output


@patch("chimera_intel.core.masint.Masint.analyze_acoustic_signature")
def test_cli_acoustic_success(mock_analyze):
    mock_analyze.return_value = [1.0, 2.0, 3.0]
    result = runner.invoke(masint_app, ["acoustic", "dummy.wav"])
    assert result.exit_code == 0
    assert "Generated Acoustic Signature" in result.stdout
    assert "1.0, 2.0, 3.0" in result.stdout


@patch("chimera_intel.core.masint.Masint.analyze_acoustic_signature", return_value=None)
def test_cli_acoustic_none(mock_analyze):
    result = runner.invoke(masint_app, ["acoustic", "dummy.wav"])
    assert result.exit_code == 0
    assert "Generated Acoustic Signature" not in result.stdout  # No output


@patch("chimera_intel.core.masint.librosa", new_callable=LibrosaPlaceholder)
def test_cli_acoustic_not_installed(mock_librosa_placeholder):
    """Tests the acoustic CLI command when librosa is not installed."""
    result = runner.invoke(masint_app, ["acoustic", "dummy.wav"])
    assert result.exit_code == 0
    # Assertion is robust enough to not need modification
    assert "librosa library not installed" in result.stdout


@patch("chimera_intel.core.masint.Masint.analyze_thermal_image")
def test_cli_thermal_success(mock_analyze, mock_thermal_image_file):
    mock_analyze.return_value = [{"x": 10, "y": 20, "width": 30, "height": 40}]
    result = runner.invoke(masint_app, ["thermal", mock_thermal_image_file])
    assert result.exit_code == 0
    assert "Detected Thermal Hotspots" in result.stdout
    assert "10" in result.stdout
    assert "40" in result.stdout


@patch("chimera_intel.core.masint.Masint.analyze_thermal_image", return_value=[])
def test_cli_thermal_no_hotspots(mock_analyze, mock_thermal_image_file):
    result = runner.invoke(masint_app, ["thermal", mock_thermal_image_file])
    assert result.exit_code == 0
    # Assertion is robust enough to not need modification
    assert "No hotspots detected" in result.stdout
