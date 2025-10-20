import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import numpy as np

# ---: Import the MAIN app and the app to be tested ---

from chimera_intel.cli import app as main_app
from chimera_intel.core.vidint import vidint_app

# ---: Manually register the app as a plugin ---
# This simulates the plugin discovery in cli.py

main_app.add_typer(vidint_app, name="vidint")

runner = CliRunner()


@pytest.fixture
def mock_video_capture(mocker):
    """Fixture to mock cv2.VideoCapture."""
    mock_cap = MagicMock()

    # ---: Reordered side_effect to match code's call order ---
    # The code calls: FRAME_COUNT, FPS, FRAME_WIDTH, FRAME_HEIGHT
    # Then extra calls for metadata: FRAME_WIDTH, FRAME_HEIGHT

    mock_cap.get.side_effect = [
        150,  # CAP_PROP_FRAME_COUNT
        30.0,  # CAP_PROP_FPS
        1920,  # CAP_PROP_FRAME_WIDTH
        1080,  # CAP_PROP_FRAME_HEIGHT
        # Extra gets for metadata print
        1920,  # CAP_PROP_FRAME_WIDTH
        1080,  # CAP_PROP_FRAME_HEIGHT
    ]
    # -----------------------------------------------------------------

    # Mock read() to return a couple of frames and then False

    mock_frame = np.zeros((1080, 1920, 3), dtype=np.uint8)
    mock_cap.read.side_effect = [(True, mock_frame), (True, mock_frame), (False, None)]
    mock_cap.release.return_value = None

    mocker.patch("cv2.VideoCapture", return_value=mock_cap)
    return mock_cap


# Patch os.path.exists WHERE IT IS USED


@patch("chimera_intel.core.vidint.os.path.exists", return_value=True)
def test_cli_analyze_video_metadata_only(mock_exists, mock_video_capture, mocker):
    mock_console_print = mocker.patch("chimera_intel.core.vidint.console.print")

    # ---: Invoke the main app with the full command ---

    result = runner.invoke(main_app, ["vidint", "analyze", "test.mp4"])

    assert result.exit_code == 0, result.output

    # ---: Corrected assertions to match vidint.py output ---

    mock_console_print.assert_any_call(
        "\n--- [bold green]Video Metadata[/bold green] ---"
    )
    mock_console_print.assert_any_call("- Resolution: 1920x1080")
    # Note: .2f formatting adds two decimals

    mock_console_print.assert_any_call("- Frame Rate: 30.00 FPS")
    mock_console_print.assert_any_call("- Duration: 5.00 seconds")


@patch("chimera_intel.core.vidint.os.path.exists", return_value=True)
@patch("cv2.imwrite")
def test_cli_analyze_video_with_frame_extraction(
    mock_imwrite, mock_exists, mock_video_capture, mocker
):
    mock_console_print = mocker.patch("chimera_intel.core.vidint.console.print")
    mocker.patch("os.makedirs")

    result = runner.invoke(
        main_app,
        [
            "vidint",
            "analyze",
            "test.mp4",
            "--extract-frames",
            "5",
            "--output-dir",
            "test_frames",
        ],
    )

    assert result.exit_code == 0, result.output

    # ---: Changed assertion to expect '1 frames' based on logic ---
    # (fps * interval) = 30 * 5 = 150.
    # range(0, frame_count, 150) with frame_count=150 only runs once.

    mock_console_print.assert_any_call(
        "\nSuccessfully extracted 1 frames to 'test_frames'."
    )
    # ---------------------------------------------------------------------


@patch("chimera_intel.core.vidint.os.path.exists", return_value=True)
def test_cli_analyze_video_with_motion_detection(
    mock_exists, mock_video_capture, mocker
):
    mock_console_print = mocker.patch("chimera_intel.core.vidint.console.print")

    result = runner.invoke(
        main_app, ["vidint", "analyze", "test.mp4", "--detect-motion"]
    )

    assert result.exit_code == 0, result.output

    # ---: Corrected assertion to match vidint.py output ---

    mock_console_print.assert_any_call("[green]No significant motion detected.[/green]")


def test_cli_analyze_video_file_not_found(mocker):
    # Patch os.path.exists WHERE IT IS USED

    mocker.patch("chimera_intel.core.vidint.os.path.exists", return_value=False)
    mock_console_print = mocker.patch("chimera_intel.core.vidint.console.print")

    # ---: Remove pytest.raises and check the result code ---

    result = runner.invoke(main_app, ["vidint", "analyze", "nonexistent.mp4"])

    assert result.exit_code == 1

    # ---: Corrected assertion to match vidint.py output ---

    mock_console_print.assert_any_call(
        "[bold red]Error:[/bold red] Video file not found at 'nonexistent.mp4'"
    )
