import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
import cv2

from chimera_intel.core.vidint import detect_motion, vidint_app

runner = CliRunner()


class TestVidint(unittest.TestCase):
    """Test cases for the Video Intelligence (VIDINT) module."""

    # --- Mock VideoCapture ---

    def setUp(self):
        """Set up a reusable mock for cv2.VideoCapture."""
        self.mock_vid_capture = MagicMock()
        self.mock_vid_capture.isOpened.return_value = True
        self.mock_vid_capture.get.side_effect = self._mock_get_property
        # Simulate a video with 2 frames for motion detection

        self.mock_vid_capture.read.side_effect = [
            (True, MagicMock()),
            (True, MagicMock()),
            (False, None),
        ]

    def _mock_get_property(self, prop_id):
        if prop_id == cv2.CAP_PROP_FRAME_COUNT:
            return 300
        if prop_id == cv2.CAP_PROP_FPS:
            return 30.0
        if prop_id == cv2.CAP_PROP_FRAME_WIDTH:
            return 1920
        if prop_id == cv2.CAP_PROP_FRAME_HEIGHT:
            return 1080
        return 0

    # --- Function Tests ---

    @patch("chimera_intel.core.vidint.cv2.VideoCapture")
    @patch("chimera_intel.core.vidint.cv2.cvtColor")
    @patch("chimera_intel.core.vidint.cv2.GaussianBlur")
    @patch("chimera_intel.core.vidint.cv2.absdiff")
    @patch("chimera_intel.core.vidint.cv2.threshold")
    @patch("chimera_intel.core.vidint.cv2.dilate")
    @patch("chimera_intel.core.vidint.cv2.findContours")
    def test_detect_motion(self, mock_contours, *args):
        """Tests the motion detection logic."""
        # Arrange

        mock_contours.return_value = (["contour1"], None)  # Simulate finding a contour
        self.mock_vid_capture.read.side_effect = [
            (True, MagicMock()),
            (True, MagicMock()),
            (False, None),
        ]

        # Act

        with patch(
            "chimera_intel.core.vidint.cv2.VideoCapture",
            return_value=self.mock_vid_capture,
        ):
            detect_motion("test.mp4")
        # Assert
        # The function should call findContours once for the single frame comparison

        mock_contours.assert_called_once()
        self.mock_vid_capture.release.assert_called_once()

    # --- CLI Tests ---

    @patch("os.path.exists", return_value=True)
    @patch("chimera_intel.core.vidint.cv2.VideoCapture")
    def test_cli_analyze_video_metadata_only(self, mock_vc, mock_exists):
        """Tests the 'vidint analyze-video' command for metadata extraction."""
        # Arrange

        mock_vc.return_value = self.mock_vid_capture

        # Act

        result = runner.invoke(vidint_app, ["analyze-video", "test.mp4"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Video Metadata", result.stdout)
        self.assertIn("Resolution: 1920x1080", result.stdout)
        self.assertIn("Duration: 10.00 seconds", result.stdout)

    @patch("os.path.exists", return_value=True)
    @patch("os.makedirs")
    @patch("chimera_intel.core.vidint.cv2.VideoCapture")
    @patch("chimera_intel.core.vidint.cv2.imwrite")
    def test_cli_analyze_video_with_frame_extraction(
        self, mock_imwrite, mock_vc, mock_makedirs, mock_exists
    ):
        """Tests the frame extraction functionality via the CLI."""
        # Arrange

        mock_vc.return_value = self.mock_vid_capture

        # Act

        result = runner.invoke(
            vidint_app,
            ["analyze-video", "test.mp4", "--extract-frames", "5"],
        )

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_makedirs.assert_called_with("video_frames")
        # 300 frames / (30 fps * 5s interval) = 2 frames

        self.assertEqual(mock_imwrite.call_count, 2)
        self.assertIn("Successfully extracted 2 frames", result.stdout)

    @patch("os.path.exists", return_value=True)
    @patch("chimera_intel.core.vidint.detect_motion")
    @patch("chimera_intel.core.vidint.cv2.VideoCapture")
    def test_cli_analyze_video_with_motion_detection(
        self, mock_vc, mock_detect_motion, mock_exists
    ):
        """Tests the motion detection functionality via the CLI."""
        # Arrange

        mock_vc.return_value = self.mock_vid_capture

        # Act

        result = runner.invoke(
            vidint_app, ["analyze-video", "test.mp4", "--detect-motion"]
        )

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_detect_motion.assert_called_once_with("test.mp4")

    def test_cli_analyze_video_file_not_found(self):
        """Tests the CLI command when the input video file does not exist."""
        result = runner.invoke(vidint_app, ["analyze-video", "nonexistent.mp4"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Video file not found", result.stdout)


if __name__ == "__main__":
    unittest.main()
