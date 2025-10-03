import unittest
from pathlib import Path
import os
import wave
from scapy.all import wrpcap, RadioTap, Dot11, Ether, IP, TCP
from PIL import Image
from click.testing import CliRunner

# Make sure the module is in the path for testing

import sys

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from chimera_intel.core.masint import (
    analyze_rf_from_pcap,
    analyze_acoustic_from_media,
    analyze_thermal_from_imagery,
    masint_cli,
)


def create_dummy_pcap(filepath: Path):
    """Creates a dummy PCAP file with a RadioTap header."""
    packet = (
        Ether()
        / IP()
        / TCP()
        / RadioTap(ChannelFrequency=2412, dbm_antsignal=-55)
        / Dot11()
    )
    wrpcap(str(filepath), [packet])


def create_dummy_wav(filepath: Path, freq: float = 60.0, duration: int = 1):
    """Creates a dummy WAV file with a specific dominant frequency."""
    sample_rate = 44100
    n_samples = int(sample_rate * duration)
    t = [float(i) / sample_rate for i in range(n_samples)]
    y = [
        int(32767.0 * 0.5 * (1 + 0.5 * (i % 2)) * ((i * freq / sample_rate) % 1))
        for i in range(n_samples)
    ]

    with wave.open(str(filepath), "w") as f:
        f.setnchannels(1)
        f.setsampwidth(2)
        f.setframerate(sample_rate)
        f.writeframesraw(bytearray(y))


def create_dummy_png(filepath: Path, width: int = 100, height: int = 100):
    """Creates a dummy PNG image."""
    img = Image.new("L", (width, height), color=128)
    # Add a bright spot

    for x in range(40, 60):
        for y in range(40, 60):
            img.putpixel((x, y), 250)
    img.save(filepath)


class TestMasintCore(unittest.TestCase):
    def setUp(self):
        """Set up test files."""
        self.test_dir = Path("test_data_masint")
        self.test_dir.mkdir(exist_ok=True)
        self.pcap_path = self.test_dir / "test.pcap"
        self.wav_path = self.test_dir / "test.wav"
        self.png_path = self.test_dir / "test.png"
        create_dummy_pcap(self.pcap_path)
        create_dummy_wav(self.wav_path)
        create_dummy_png(self.png_path)

    def tearDown(self):
        """Clean up test files."""
        os.remove(self.pcap_path)
        os.remove(self.wav_path)
        os.remove(self.png_path)
        self.test_dir.rmdir()

    def test_analyze_rf_from_pcap(self):
        """Test RF analysis from a PCAP file."""
        results = analyze_rf_from_pcap(self.pcap_path)
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0].frequency_mhz, 2412)
        self.assertEqual(results[0].power_dbm, -55)

    def test_analyze_acoustic_from_media(self):
        """Test acoustic analysis from a WAV file."""
        results = analyze_acoustic_from_media(self.wav_path)
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        self.assertAlmostEqual(results[0].dominant_frequency_hz, 60.0, delta=1.0)
        self.assertEqual(results[0].signature_type, "Power Grid Hum")

    def test_analyze_thermal_from_imagery_local(self):
        """Test (simulated) thermal analysis from a local image file."""
        # Note: The function expects a URL, but we can adapt for local testing
        # by passing the file path as a string (the function doesn't validate the URL format)

        results = analyze_thermal_from_imagery(f"file://{self.png_path.resolve()}")
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        self.assertGreater(results[0].max_temperature_celsius, 95)  # Should be high

    def test_cli_commands(self):
        """Test the MASINT CLI commands."""
        runner = CliRunner()
        # Test RF

        rf_result = runner.invoke(masint_cli, ["analyze-rf", str(self.pcap_path)])
        self.assertEqual(rf_result.exit_code, 0)
        self.assertIn("2412", rf_result.output)
        # Test Acoustic

        acoustic_result = runner.invoke(
            masint_cli, ["analyze-acoustic", str(self.wav_path)]
        )
        self.assertEqual(acoustic_result.exit_code, 0)
        self.assertIn("Power Grid Hum", acoustic_result.output)
        # Test Thermal

        thermal_result = runner.invoke(
            masint_cli, ["analyze-thermal", f"file://{self.png_path.resolve()}"]
        )
        self.assertEqual(thermal_result.exit_code, 0)
        self.assertIn("Simulated", thermal_result.output)


if __name__ == "__main__":
    unittest.main()
