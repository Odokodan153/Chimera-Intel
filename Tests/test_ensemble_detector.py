import unittest
import pathlib
import shutil
from unittest.mock import patch, ANY
from typer.testing import CliRunner
import cv2
import numpy as np

# Module to test
from chimera_intel.core.ensemble_detector import (
    ensemble_app,
    run_ensemble_analysis,
    analyze_temporal_model
)

# Schemas needed for mocking
from chimera_intel.core.schemas import DeepfakeAnalysisResult, EnsembleAnalysisResult
from chimera_intel.core.ensemble_detector import (
    TemporalAnalysisResult,
    SyntheticVoiceAnalysisResult
)

runner = CliRunner()

# --- Test Data Setup ---
TEST_MEDIA_DIR = pathlib.Path("test_ensemble_media")
TEST_VID_FILE = TEST_MEDIA_DIR / "test_video.mp4"


def create_dummy_video():
    """Creates a small, real video file for testing temporal analysis."""
    if TEST_MEDIA_DIR.exists():
        shutil.rmtree(TEST_MEDIA_DIR)
    TEST_MEDIA_DIR.mkdir()
    
    try:
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        writer = cv2.VideoWriter(str(TEST_VID_FILE), fourcc, 30.0, (100, 100))
        for i in range(60):
            # Create a frame with a moving square
            frame = np.zeros((100, 100, 3), dtype=np.uint8)
            x_pos = i * 1 # Move square
            frame[40:60, x_pos:x_pos+20] = [255, 0, 0] # Blue square
            writer.write(frame)
        writer.release()
    except Exception as e:
        print(f"Warning: Could not create test video: {e}. Temporal test may fail.")


class TestEnsembleDetector(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        create_dummy_video()
        
    @classmethod
    def tearDownClass(cls):
        if TEST_MEDIA_DIR.exists():
            shutil.rmtree(TEST_MEDIA_DIR)

    def test_01_analyze_temporal_model_real_video(self):
        """Tests the temporal analysis on a real, generated video file."""
        if not TEST_VID_FILE.exists():
            self.skipTest("Dummy video file was not created.")
            
        result = analyze_temporal_model(TEST_VID_FILE)
        
        self.assertIsNone(result.error)
        self.assertGreater(result.temporal_inconsistency_score, 0) # It has motion
        self.assertIn("Average optical flow", result.details)

    @patch("chimera_intel.core.ensemble_detector.detect_synthetic_voice")
    @patch("chimera_intel.core.ensemble_detector.analyze_temporal_model")
    @patch("chimera_intel.core.ensemble_detector.deepfake_multimodal_scan")
    def test_02_run_ensemble_analysis_logic(
        self, mock_deepfake_scan, mock_temporal_analysis, mock_voice_detect
    ):
        """Tests the ensemble logic with mocked component outputs."""
        
        # Arrange
        # 1. Frame-level mock (High fake)
        mock_deepfake_scan.return_value = DeepfakeAnalysisResult(
            is_deepfake=True, confidence=0.90,
            inconsistencies=["High average fake probability (0.90)"]
        )
        
        # 2. Temporal mock (Low fake)
        mock_temporal_analysis.return_value = TemporalAnalysisResult(
            temporal_inconsistency_score=0.10,
            details="Average optical flow std. dev: 0.5"
        )
        
        # 3. Audio mock (High fake)
        mock_voice_detect.return_value = SyntheticVoiceAnalysisResult(
            is_synthetic=True, confidence=0.80,
            details="Classifier prediction: synthetic (Confidence: 80.00%)"
        )
        
        # Act
        result = run_ensemble_analysis(TEST_VID_FILE)
        
        # Assert
        self.assertIsNone(result.error)
        
        # Check ensemble calculation: (0.90 * 0.5) + (0.10 * 0.2) + (0.80 * 0.3)
        # 0.45 + 0.02 + 0.24 = 0.71
        self.assertAlmostEqual(result.final_fake_probability, 0.71)
        
        # Check explainability report
        report = result.explainability_report
        self.assertIn("0.90", report["suspicious_visual_frames"])
        self.assertIn("No significant artifacts found", report["suspicious_temporal_segments"])
        self.assertIn("0.80", report["suspicious_audio_segments"])

    @patch("chimera_intel.core.ensemble_detector.run_ensemble_analysis")
    def test_03_cli_run_command(self, mock_run_ensemble):
        """Tests the main 'run' CLI command."""
        if not TEST_VID_FILE.exists():
            self.skipTest("Dummy video file was not created.")
            
        # Arrange
        mock_run_ensemble.return_value = EnsembleAnalysisResult(
            final_fake_probability=0.71,
            frame_analysis=DeepfakeAnalysisResult(is_deepfake=True, confidence=0.9),
            temporal_analysis=TemporalAnalysisResult(temporal_inconsistency_score=0.1),
            voice_analysis=SyntheticVoiceAnalysisResult(is_synthetic=True, confidence=0.8),
            explainability_report={"summary": "Final synthetic probability: 0.71"}
        )
        
        # Act
        result = runner.invoke(ensemble_app, ["run", str(TEST_VID_FILE)])
        
        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Ensemble Analysis Complete", result.output)
        self.assertIn("Ensemble Result", result.output)
        self.assertIn("71.00%", result.output)
        self.assertIn("Explainability Report", result.output)
        
if __name__ == "__main__":
    unittest.main()