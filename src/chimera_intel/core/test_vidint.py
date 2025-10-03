import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import os

# The application instance to be tested

from chimera_intel.core.vidint import vidint_app

runner = CliRunner()


@pytest.fixture
def mock_cv2(mocker):
    """Mocks the cv2.VideoCapture and cv2.imwrite calls."""
    mock_video_capture = MagicMock()
    mock_video_capture.isOpened.return_value = True
    mock_video_capture.get.side_effect = [
        1200,
        30.0,
        1920,
        1080,
    ]  # Frame count, FPS, width, height
    mock_video_capture.read.return_value = (True, "fake_image_data")

    mocker.patch("cv2.VideoCapture", return_value=mock_video_capture)
    mocker.patch("cv2.imwrite")
    return mock_video_capture


def test_analyze_video_metadata_success(mocker, mock_cv2):
    """Tests successful extraction of video metadata."""
    mocker.patch("os.path.exists", return_value=True)
    result = runner.invoke(vidint_app, ["analyze-video", "fake_video.mp4"])

    assert result.exit_code == 0
    assert "Video Metadata" in result.stdout
    assert "Resolution: 1920x1080" in result.stdout
    assert "Duration: 40.00 seconds" in result.stdout


def test_analyze_video_extract_frames(mocker, mock_cv2):
    """Tests the frame extraction feature."""
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("os.makedirs")

    result = runner.invoke(
        vidint_app, ["analyze-video", "fake_video.mp4", "--extract-frames", "10"]
    )

    assert result.exit_code == 0
    assert "Successfully extracted 4 frames" in result.stdout


def test_analyze_video_file_not_found():
    """Tests the command when the video file does not exist."""
    result = runner.invoke(vidint_app, ["analyze-video", "non_existent.mp4"])

    assert result.exit_code == 1
    assert "Error: Video file not found" in result.stdout
