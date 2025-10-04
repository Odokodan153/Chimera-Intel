# Tests/test_masint.py

import unittest
import numpy as np
import cv2
from scapy.all import Ether, IP, TCP, wrpcap
from src.chimera_intel.core.masint import Masint

# A dummy audio file is needed for the acoustic test.
# We will create one if librosa is available.

try:
    import soundfile as sf

    librosa_installed = True
except ImportError:
    librosa_installed = False


class TestMasint(unittest.TestCase):
    def setUp(self):
        self.masint = Masint()
        # Create a dummy pcap file

        self.pcap_file = "test.pcap"
        packets = [Ether() / IP(dst="8.8.8.8") / TCP() for _ in range(10)]
        wrpcap(self.pcap_file, packets)

        # Create a dummy thermal image

        self.image_file = "thermal.png"
        img = np.zeros((100, 100), dtype=np.uint8)
        cv2.rectangle(img, (20, 20), (40, 40), 255, -1)  # A "hotspot"
        cv2.imwrite(self.image_file, img)

        # Create a dummy audio file

        if librosa_installed:
            self.audio_file = "test.wav"
            samplerate = 22050
            data = np.random.randn(2 * samplerate)  # 2 seconds of noise
            sf.write(self.audio_file, data, samplerate)

    def test_analyze_rf_pcap(self):
        signature = self.masint.analyze_rf_pcap(self.pcap_file)
        self.assertIsNotNone(signature)
        self.assertEqual(signature["packet_count"], 10)

    @unittest.skipIf(not librosa_installed, "librosa or soundfile not installed")
    def test_analyze_acoustic_signature(self):
        signature = self.masint.analyze_acoustic_signature(self.audio_file)
        self.assertIsNotNone(signature)
        self.assertEqual(len(signature), 13)  # 13 MFCCs

    def test_analyze_thermal_image(self):
        hotspots = self.masint.analyze_thermal_image(self.image_file, threshold=200)
        self.assertIsNotNone(hotspots)
        self.assertEqual(len(hotspots), 1)
        self.assertEqual(hotspots[0]["x"], 20)

    def tearDown(self):
        import os

        os.remove(self.pcap_file)
        os.remove(self.image_file)
        if librosa_installed and os.path.exists(self.audio_file):
            os.remove(self.audio_file)


if __name__ == "__main__":
    unittest.main()
