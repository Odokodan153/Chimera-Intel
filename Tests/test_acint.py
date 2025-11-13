# Tests/test_acint.py

import unittest
import os
import tempfile
import numpy as np
import soundfile as sf
from src.chimera_intel.core.acint import AcousticIntelligence

class TestAcousticIntelligence(unittest.TestCase):

    def setUp(self):
        """Set up the test environment."""
        self.acint = AcousticIntelligence()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sample_rate = 22050
        
        # Create dummy audio files for testing
        self.engine_file = self._create_dummy_wav("engine.wav", freq=120)
        self.gunshot_file = self._create_dummy_wav("gunshot.wav", freq=1000, duration=0.5)
        self.ambience_file = self._create_dummy_wav("ambience.wav", freq=50, noise_level=0.1)
        self.unknown_file = self._create_dummy_wav("unknown.wav", freq=500)

    def _create_dummy_wav(self, name, freq, duration=2, noise_level=0.01):
        """Helper function to create a dummy WAV file."""
        t = np.linspace(0., float(duration), int(self.sample_rate * duration), endpoint=False)
        amplitude = np.iinfo(np.int16).max * 0.5
        
        # Create a simple sine wave
        signal = amplitude * np.sin(2. * np.pi * freq * t)
        
        # Add some noise
        noise = noise_level * amplitude * np.random.normal(size=len(t))
        
        final_signal = (signal + noise).astype(np.int16)
        
        file_path = os.path.join(self.temp_dir.name, name)
        
        # Use soundfile to write the WAV
        sf.write(file_path, final_signal, self.sample_rate)
        
        return file_path

    def tearDown(self):
        """Clean up the test environment."""
        self.temp_dir.cleanup()

    def test_01_add_to_library(self):
        """Test adding a signature to the library."""
        result = self.acint.add_to_library(self.engine_file, "truck_engine")
        self.assertTrue(result)
        self.assertIn("truck_engine", self.acint.signature_library)
        self.assertIsInstance(self.acint.signature_library["truck_engine"], np.ndarray)
        self.assertEqual(self.acint.signature_library["truck_engine"].shape, (20,)) # 20 MFCCs

    def test_02_identify_sound(self):
        """Test identifying a known sound."""
        self.acint.add_to_library(self.engine_file, "truck_engine")
        self.acint.add_to_library(self.gunshot_file, "gunshot")

        # Create a slightly different version of the engine sound
        engine_copy = self._create_dummy_wav("engine_copy.wav", freq=121, noise_level=0.02)
        
        result_name, result_dist = self.acint.identify_sound(engine_copy, threshold=0.5)
        
        self.assertEqual(result_name, "truck_engine")
        self.assertIsNotNone(result_dist)
        self.assertLess(result_dist, 0.5)

    def test_03_identify_unknown_sound(self):
        """Test identifying an unknown sound."""
        self.acint.add_to_library(self.engine_file, "truck_engine")
        
        result_name, result_dist = self.acint.identify_sound(self.unknown_file, threshold=0.5)
        
        self.assertEqual(result_name, "Unknown Signature")
        self.assertGreater(result_dist, 0.5)

    def test_04_detect_anomaly(self):
        """Test detecting an anomalous sound."""
        self.acint.add_to_library(self.ambience_file, "baseline_ambience")

        # Test non-anomaly (another similar ambience file)
        ambience_copy = self._create_dummy_wav("ambience_copy.wav", freq=51, noise_level=0.11)
        result_normal = self.acint.detect_anomaly(ambience_copy, "baseline_ambience", threshold=1.0)
        
        self.assertFalse(result_normal["is_anomaly"])
        self.assertLess(result_normal["distance"], 1.0)

        # Test anomaly (gunshot file)
        result_anomaly = self.acint.detect_anomaly(self.gunshot_file, "baseline_ambience", threshold=1.0)
        
        self.assertTrue(result_anomaly["is_anomaly"])
        self.assertGreater(result_anomaly["distance"], 1.0)

    def test_05_save_and_load_library(self):
        """Test saving and loading the signature library."""
        lib_path = os.path.join(self.temp_dir.name, "test_lib.json")
        self.acint.add_to_library(self.engine_file, "truck_engine")
        self.acint.save_library(lib_path)
        
        # Create a new instance to load into
        new_acint = AcousticIntelligence()
        self.assertNotIn("truck_engine", new_acint.signature_library)
        
        new_acint.load_library(lib_path)
        
        self.assertIn("truck_engine", new_acint.signature_library)
        self.assertTrue(np.array_equal(
            self.acint.signature_library["truck_engine"],
            new_acint.signature_library["truck_engine"]
        ))

    def test_06_handle_missing_files(self):
        """Test error handling for missing files."""
        result = self.acint.add_to_library("non_existent_file.wav", "missing")
        self.assertFalse(result)
        
        result_name, result_dist = self.acint.identify_sound("non_existent_file.wav")
        self.assertEqual(result_name, "Error processing file")
        self.assertIsNone(result_dist)

    def test_07_detect_anomaly_missing_baseline(self):
        """Test anomaly detection with a missing baseline."""
        result = self.acint.detect_anomaly(self.gunshot_file, "non_existent_baseline")
        self.assertIn("error", result)
        self.assertEqual(result["error"], "Baseline signature 'non_existent_baseline' not in library.")

if __name__ == '__main__':
    unittest.main()