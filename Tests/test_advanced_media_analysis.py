import unittest
import os
import json
from unittest.mock import patch
from pathlib import Path
import logging
import pytest
# --- Dependencies for creating test files ---
try:
    import numpy as np
    import cv2
    from PIL import Image
    import soundfile as sf
except ImportError:
    print("Test setup ERROR: Missing dependencies. Please run: pip install numpy opencv-python-headless Pillow librosa soundfile")
    raise
# --------------------------------------------

# --- Import Typer for CLI testing ---
try:
    from typer.testing import CliRunner
except ImportError:
    print("Test setup ERROR: Missing 'typer'. Please run: pip install typer")
    raise
# ------------------------------------

from chimera_intel.core.advanced_media_analysis import (
    ForensicArtifactScan,
    DeepfakeMultimodal,
    ContentProvenanceCheck,
    AiGenerationTracer,
    HAS_FFPROBE,
    cli_app, 
    encode_message_in_image, 
    decode_message_from_image
)

# Disable logging from the module to keep test output clean
logging.disable(logging.WARNING)

# Initialize the CLI runner
runner = CliRunner()


class TestAdvancedMediaAnalysis(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Generate real test media files once for all tests.
        """
        cls.test_files = []
        
        # 1. Create a standard JPEG image
        cls.test_img_path = Path("test_img_standard.jpg")
        try:
            img_arr = np.zeros((100, 100, 3), dtype=np.uint8)
            img_arr[25:75, 25:75] = [0, 255, 0] # Green square
            pil_img = Image.fromarray(img_arr, 'RGB')
            pil_img.save(cls.test_img_path, quality=90)
            cls.test_files.append(cls.test_img_path)
        except Exception as e:
            print(f"Warning: Could not create test image: {e}")

        # 2. Create an image with AI metadata
        cls.ai_img_path = Path("test_img_ai_metadata.jpg")
        try:
            exif_data = Image.Exif()
            exif_data[305] = "Stable Diffusion 1.5" # 305 = Software Tag
            pil_img.save(cls.ai_img_path, quality=95, exif=exif_data.tobytes())
            cls.test_files.append(cls.ai_img_path)
        except Exception as e:
            print(f"Warning: Could not create AI test image: {e}")

        # 3. Create a silent video file
        cls.test_vid_path = Path("test_video_silent.mp4")
        if HAS_FFPROBE:
            try:
                fourcc = cv2.VideoWriter_fourcc(*'mp4v')
                writer = cv2.VideoWriter(str(cls.test_vid_path), fourcc, 30.0, (100, 100))
                for i in range(60): writer.write(np.zeros((100, 100, 3), dtype=np.uint8))
                writer.release()
                cls.test_files.append(cls.test_vid_path)
            except Exception as e:
                print(f"Warning: Could not create test video: {e}")

        # 4. Create an audio file with an unnaturally stable pitch
        cls.test_audio_path = Path("test_audio_sine_wave.wav")
        try:
            sr = 22050; T = 2.0
            t = np.linspace(0., T, int(sr * T), endpoint=False)
            sig = 0.5 * np.sin(2 * np.pi * 440 * t) # A pure 440Hz tone
            sf.write(str(cls.test_audio_path), sig, sr)
            cls.test_files.append(cls.test_audio_path)
        except Exception as e:
            print(f"Warning: Could not create test audio: {e}")


    @classmethod
    def tearDownClass(cls):
        """ Clean up all generated test files. """
        for f in cls.test_files:
            if f.exists():
                os.remove(f)

    # -------------------------------------------------
    # 1. Unit Tests for Core Logic
    # (These tests are mostly unchanged)
    # -------------------------------------------------

    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            ForensicArtifactScan("non_existent_file.jpg")

    def test_forensic_artifact_scan_ela(self):
        self.assertTrue(self.test_img_path.exists())
        scanner = ForensicArtifactScan(str(self.test_img_path))
        results = scanner._run_ela()
        self.assertEqual(results['status'], 'completed')
        self.assertLess(results['mean_ela_value'], 3.0)
        self.assertFalse(results['is_suspicious'])

    def test_forensic_artifact_scan_clone(self):
        self.assertTrue(self.test_img_path.exists())
        scanner = ForensicArtifactScan(str(self.test_img_path))
        if not scanner.sift:
            self.skipTest("SIFT not available. Install 'opencv-contrib-python-headless'")
        results = scanner._run_clone_detection()
        self.assertEqual(results['status'], 'completed')
        self.assertEqual(results['cloned_keypoints_found'], 0)

    @unittest.skipIf(not HAS_FFPROBE, "ffprobe (ffmpeg) not found. Skipping audio tests.")
    def test_deepfake_audio_positive_heuristic(self):
        self.assertTrue(self.test_audio_path.exists())
        detector = DeepfakeMultimodal(str(self.test_audio_path))
        results = detector.analyze()
        self.assertEqual(results['audio_analysis']['status'], 'completed')
        self.assertGreater(results['audio_analysis']['deepfake_score'], 0.9)
        self.assertGreater(results['overall_deepfake_score'], 0.9)

    @patch('chimera_intel.core.advanced_media_analysis.c2pa.read_file')
    def test_content_provenance_check_not_found(self, mock_c2pa_read):
        mock_c2pa_read.return_value = None
        checker = ContentProvenanceCheck(str(self.test_img_path))
        results = checker.check_provenance()
        self.assertEqual(results['status'], 'not_found')
        self.assertFalse(results['valid'])

    def test_ai_generation_tracer_positive_metadata(self):
        self.assertTrue(self.ai_img_path.exists())
        tracer = AiGenerationTracer(str(self.ai_img_path))
        results = tracer.trace_generation()
        self.assertTrue(results['is_ai_generated'])
        self.assertEqual(results['confidence_score'], 1.0)
        self.assertEqual(results['suspected_model'], 'Stable Diffusion 1.5')

    def test_ai_generation_tracer_negative(self):
        self.assertTrue(self.test_img_path.exists())
        tracer = AiGenerationTracer(str(self.test_img_path))
        results = tracer.trace_generation()
        self.assertFalse(results['is_ai_generated'])
        self.assertEqual(results['confidence_score'], 0.0)

    # -------------------------------------------------
    # 2. Integration Tests for CLI Commands (NEW)
    # -------------------------------------------------

    def test_cli_analyze_command(self):
        """Test the 'analyze' CLI command."""
        result = runner.invoke(cli_app, ["analyze", str(self.ai_img_path)])
        self.assertEqual(result.exit_code, 0)
        try:
            data = json.loads(result.stdout)
            self.assertEqual(data['ai_generation_trace']['suspected_model'], 'Stable Diffusion 1.5')
            self.assertEqual(data['forensic_artifacts']['status'], 'completed')
            self.assertEqual(data['content_provenance']['status'], 'not_found') # Mock is not active here
        except json.JSONDecodeError:
            self.fail(f"CLI output was not valid JSON: {result.stdout}")

    def test_cli_forensics_command(self):
        """Test the 'forensics' CLI command."""
        result = runner.invoke(cli_app, ["forensics", str(self.test_img_path)])
        self.assertEqual(result.exit_code, 0)
        try:
            data = json.loads(result.stdout)
            self.assertEqual(data['ela_result']['status'], 'completed')
            self.assertEqual(data['clone_detection']['is_suspicious'], False)
        except json.JSONDecodeError:
            self.fail(f"CLI output was not valid JSON: {result.stdout}")

    @unittest.skipIf(not HAS_FFPROBE, "ffprobe (ffmpeg) not found. Skipping CLI audio test.")
    def test_cli_deepfake_command_audio(self):
        """Test the 'deepfake' CLI command on audio."""
        result = runner.invoke(cli_app, ["deepfake", str(self.test_audio_path)])
        self.assertEqual(result.exit_code, 0)
        try:
            data = json.loads(result.stdout)
            self.assertGreater(data['overall_deepfake_score'], 0.9)
            self.assertEqual(data['audio_analysis']['status'], 'completed')
        except json.JSONDecodeError:
            self.fail(f"CLI output was not valid JSON: {result.stdout}")

    def test_cli_provenance_command(self):
        """Test the 'provenance' CLI command."""
        # We can patch c2pa here just for the CLI test
        with patch('chimera_intel.core.advanced_media_analysis.c2pa.read_file', return_value=None):
            result = runner.invoke(cli_app, ["provenance", str(self.test_img_path)])
            self.assertEqual(result.exit_code, 0)
            try:
                data = json.loads(result.stdout)
                self.assertEqual(data['status'], 'not_found')
            except json.JSONDecodeError:
                self.fail(f"CLI output was not valid JSON: {result.stdout}")

    def test_cli_ai_trace_command(self):
        """Test the 'ai-trace' CLI command."""
        result = runner.invoke(cli_app, ["ai-trace", str(self.ai_img_path)])
        self.assertEqual(result.exit_code, 0)
        try:
            data = json.loads(result.stdout)
            self.assertEqual(data['is_ai_generated'], True)
            self.assertEqual(data['suspected_model'], 'Stable Diffusion 1.5')
        except json.JSONDecodeError:
            self.fail(f"CLI output was not valid JSON: {result.stdout}")

    def test_cli_file_not_found(self):
        """Test CLI command failure on a missing file."""
        result = runner.invoke(cli_app, ["analyze", "non_existent_file.jpg"])
        self.assertEqual(result.exit_code, 0) # Typer commands handle exceptions and print to console
        self.assertIn("File not found", result.stdout)
@pytest.fixture
def sample_image(tmp_path):
    """Create a dummy PNG image for testing."""
    img_path = tmp_path / "test_image.png"
    img = Image.new('RGB', (100, 100), color = 'blue')
    img.save(img_path)
    return img_path

def test_encode_decode_logic(sample_image):
    """Test the core steganography functions."""
    message = "This is a 🕵️ secret!"
    
    # 1. Encode
    encoded_img = encode_message_in_image(str(sample_image), message)
    
    # Check that the image is different
    original_data = list(Image.open(sample_image).getdata())
    encoded_data = list(encoded_img.getdata())
    assert original_data != encoded_data
    
    # 2. Save and Decode
    encoded_path = sample_image.parent / "encoded.png"
    encoded_img.save(encoded_path)
    
    decoded_message = decode_message_from_image(str(encoded_path))
    
    assert decoded_message == message

def test_decode_no_message(sample_image):
    """Test decoding an image with no message."""
    decoded_message = decode_message_from_image(str(sample_image))
    assert decoded_message is None

def test_message_too_long(sample_image):
    """Test that encoding fails if the message is too long."""
    # 100x100 pixels = 10,000 pixels * 3 channels/pixel = 30,000 bits
    # 30,000 bits / 8 bits/byte = 3,750 bytes
    long_message = "A" * 4000 
    
    with pytest.raises(ValueError, match="Message is too long"):
        encode_message_in_image(str(sample_image), long_message)

def test_cli_encode_decode(sample_image, tmp_path):
    """Test the full CLI round-trip."""
    message = "cli test"
    output_path = tmp_path / "cli_encoded.png"

    # 1. Encode command
    result_encode = runner.invoke(
        cli_app,
        [
            "encode-covert",
            str(sample_image),
            "--message", message,
            "--output", str(output_path)
        ]
    )
    assert result_encode.exit_code == 0
    assert "Message successfully hidden" in result_encode.stdout
    assert os.path.exists(output_path)
    
    # 2. Decode command
    result_decode = runner.invoke(
        cli_app,
        [
            "decode-covert",
            str(output_path)
        ]
    )
    assert result_decode.exit_code == 0
    assert "Message Found" in result_decode.stdout
    assert message in result_decode.stdout

if __name__ == "__main__":
    unittest.main()