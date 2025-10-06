import pytest
from typer.testing import CliRunner
from PIL import Image
from unittest.mock import patch, MagicMock
from chimera_intel.core.imint import imint_app, analyze_image_metadata
from chimera_intel.core.schemas import ImageAnalysisResult

runner = CliRunner()

# --- Fixtures ---


@pytest.fixture
def mock_image_file(tmp_path):
    """Creates a mock, blank image file for testing purposes."""
    image_path = tmp_path / "test_image.png"
    Image.new("RGB", (100, 100), color="red").save(image_path)
    return str(image_path)


@pytest.fixture(autouse=True)
def mock_db_and_save(mocker):
    """Mocks the database and file saving utility functions for all tests."""
    mocker.patch("chimera_intel.core.imint.save_or_print_results")
    mocker.patch("chimera_intel.core.imint.save_scan_to_db")


# --- Tests for Visual Intelligence (VISINT) ---


@pytest.fixture
def mock_gemini(mocker):
    """Mocks the google.generativeai library."""
    mock_model = MagicMock()
    mock_model.generate_content.return_value.text = "Mocked AI Response"
    mock_genai = MagicMock()
    mock_genai.GenerativeModel.return_value = mock_model
    return mocker.patch("chimera_intel.core.imint.genai", mock_genai)


def test_analyze_content_success(mock_image_file, mock_gemini):
    """Tests the analyze-content command with a valid feature."""
    result = runner.invoke(
        imint_app, ["analyze-content", mock_image_file, "--feature", "body-language"]
    )
    assert result.exit_code == 0
    assert "Visual Analysis Result" in result.stdout
    assert "Mocked AI Response" in result.stdout


def test_analyze_content_invalid_feature(mock_image_file):
    """Tests the command with an invalid feature flag."""
    result = runner.invoke(
        imint_app, ["analyze-content", mock_image_file, "--feature", "invalid-feature"]
    )
    assert result.exit_code == 1
    assert "Error: Invalid feature 'invalid-feature'" in result.stdout


def test_analyze_content_no_api_key(mocker, mock_image_file):
    """Tests that the command fails if the Google API key is missing."""
    mocker.patch("chimera_intel.core.imint.API_KEYS.google_api_key", None)
    result = runner.invoke(
        imint_app, ["analyze-content", mock_image_file, "--feature", "ocr"]
    )
    assert result.exit_code == 1
    assert "GOOGLE_API_KEY not found" in result.stdout


# --- Tests for Satellite Analysis ---


@patch(
    "chimera_intel.core.imint.perform_object_detection",
    return_value={"car": 5, "airplane": 1},
)
def test_analyze_satellite_success(mock_detection, mock_image_file):
    """Tests the analyze-satellite command with the object-detection feature."""
    result = runner.invoke(
        imint_app,
        [
            "analyze-satellite",
            "--coords",
            "40.7128,-74.0060",
            "--feature",
            "object-detection",
            "--image",
            mock_image_file,
        ],
    )
    assert result.exit_code == 0
    assert "Object Detection Results" in result.stdout
    assert "Detected 5 instance(s) of 'car'" in result.stdout
    assert "Detected 1 instance(s) of 'airplane'" in result.stdout


def test_analyze_satellite_no_image_for_object_detection():
    """Tests that satellite analysis fails if object-detection is requested without an image."""
    result = runner.invoke(
        imint_app,
        [
            "analyze-satellite",
            "--coords",
            "40.7128,-74.0060",
            "--feature",
            "object-detection",
        ],
    )
    assert result.exit_code == 1
    assert (
        "Error: The --image option is required for object detection." in result.stdout
    )


# --- Tests for Metadata Analysis ---


@patch("chimera_intel.core.imint.Image.open")
def test_analyze_image_metadata_success(mock_image_open):
    """Tests successful extraction of EXIF data from an image."""
    mock_image = MagicMock()
    mock_image._getexif.return_value = {271: "TestCam", 272: "TestModel"}
    mock_image_open.return_value.__enter__.return_value = mock_image

    result = analyze_image_metadata("test.jpg")

    assert isinstance(result, ImageAnalysisResult)
    assert result.error is None
    assert result.exif_data is not None
    assert result.exif_data.Make == "TestCam"
    assert result.exif_data.Model == "TestModel"


@patch("chimera_intel.core.imint.Image.open")
def test_analyze_image_metadata_no_exif(mock_image_open):
    """Tests the case where an image has no EXIF metadata."""
    mock_image = MagicMock()
    mock_image._getexif.return_value = None
    mock_image_open.return_value.__enter__.return_value = mock_image

    result = analyze_image_metadata("no_exif.png")

    assert result.error is None
    assert result.exif_data is None
    assert result.message == "No EXIF metadata found."


@patch(
    "chimera_intel.core.imint.Image.open",
    side_effect=FileNotFoundError("File does not exist"),
)
def test_analyze_image_metadata_file_error(mock_image_open):
    """Tests error handling when the image file cannot be opened."""
    result = analyze_image_metadata("nonexistent.jpg")

    assert result.error is not None
    assert "Could not process image" in result.error


def test_run_metadata_command_flow(mocker, mock_image_file):
    """
    Tests the full 'metadata' command flow, ensuring the core function is called.
    """
    mock_analyze = mocker.patch(
        "chimera_intel.core.imint.analyze_image_metadata",
        return_value=ImageAnalysisResult(file_path=mock_image_file),
    )

    result = runner.invoke(imint_app, ["metadata", mock_image_file])

    assert result.exit_code == 0
    mock_analyze.assert_called_once_with(mock_image_file)
