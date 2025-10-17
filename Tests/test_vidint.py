import pytest
from typer.testing import CliRunner
from unittest.mock import MagicMock, patch
import cv2
import numpy as np

# The application instance to be tested

from chimera_intel.core.vidint import vidint_app

# Create a CliRunner for invoking the app in tests

runner = CliRunner()


@pytest.fixture
def mock_video_capture():
    """
    A pytest fixture that mocks the cv2.VideoCapture object.
    This prevents actual file I/O and provides consistent video properties for testing.
    """
    with patch("chimera_intel.core.vidint.cv2.VideoCapture") as mock_video:
        mock_vid = MagicMock()
        mock_vid.isOpened.return_value = True

        def _mock_get_property(prop_id):
            if prop_id == cv2.CAP_PROP_FRAME_COUNT:
                return 300  # 10 seconds at 30 fps
            if prop_id == cv2.CAP_PROP_FPS:
                return 30.0
            if prop_id == cv2.CAP_PROP_FRAME_WIDTH:
                return 1920
            if prop_id == cv2.CAP_PROP_FRAME_HEIGHT:
                return 1080
            return 0

        mock_vid.get.side_effect = _mock_get_property

        dummy_frame = np.zeros((1080, 1920, 3), dtype=np.uint8)
        mock_vid.read.side_effect = [
            (True, dummy_frame),
            (True, dummy_frame),
            (True, dummy_frame),
            (False, None),  # Simulate end of video
        ]
        mock_video.return_value = mock_vid
        yield mock_vid


@patch("os.path.exists", return_value=True)
def test_cli_analyze_video_metadata_only(mock_exists, mock_video_capture):
    """
    Tests the 'analyze-video' command for correct metadata extraction.
    """
    result = runner.invoke(vidint_app, ["analyze-video", "test.mp4"])

    assert result.exit_code == 0, result.output
    assert "Video Metadata" in result.stdout
    assert "Resolution: 1920x1080" in result.stdout
    assert "Duration: 10.00 seconds" in result.stdout


@patch("os.path.exists", return_value=True)
@patch("os.makedirs")
@patch("chimera_intel.core.vidint.cv2.imwrite")
def test_cli_analyze_video_with_frame_extraction(
    mock_imwrite, mock_makedirs, mock_exists, mock_video_capture
):
    """
    Tests the frame extraction functionality via the CLI (--extract-frames).
    """
    result = runner.invoke(
        vidint_app,
        ["analyze-video", "test.mp4", "--extract-frames", "5"],
    )

    assert result.exit_code == 0, result.output
    mock_makedirs.assert_called_once_with("video_frames")
    # Calculation: 300 frames / (30 fps * 5s interval) = 2 frames should be saved

    assert mock_imwrite.call_count == 2
    assert "Successfully extracted 2 frames" in result.stdout


@patch("os.path.exists", return_value=True)
@patch("chimera_intel.core.vidint.run_motion_detection")
def test_cli_analyze_video_with_motion_detection(
    mock_run_motion_detection, mock_exists, mock_video_capture
):
    """
    Tests the motion detection functionality via the CLI (--detect-motion).
    """
    result = runner.invoke(vidint_app, ["analyze-video", "test.mp4", "--detect-motion"])

    assert result.exit_code == 0, result.output
    mock_run_motion_detection.assert_called_once_with("test.mp4")


@patch("os.path.exists", return_value=False)
def test_cli_analyze_video_file_not_found(mock_exists):
    """
    Tests that the command fails correctly when the input video file does not exist.
    """
    result = runner.invoke(vidint_app, ["analyze-video", "nonexistent.mp4"])

    assert result.exit_code == 1
    assert "Error: Video file not found" in result.stdout
