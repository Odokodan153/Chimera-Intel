import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import numpy as np

# Mock libraries before they are imported by the module
# This allows testing the CLI even if the libs are not installed
mock_cv2 = MagicMock()
mock_face_recognition = MagicMock()

# --- Mock Fixture for successful library import ---
@pytest.fixture(scope="module")
def mock_face_libs(module_mocker):
    module_mocker.patch.dict(
        "sys.modules",
        {
            "cv2": mock_cv2,
            "face_recognition": mock_face_recognition,
        },
    )
    # Re-patch the constant in the biomint module
    module_mocker.patch("chimera_intel.core.biomint.FACE_LIBS_AVAILABLE", True)
    yield mock_cv2, mock_face_recognition

# --- Mock Fixture for failed library import ---
@pytest.fixture(scope="module")
def mock_face_libs_unavailable(module_mocker):
    module_mocker.patch("chimera_intel.core.biomint.FACE_LIBS_AVAILABLE", False)
    yield

# Now import the module to be tested
from chimera_intel.core.biomint import biomint_app, analyze_face, compare_voices

runner = CliRunner()

# --- Face Analysis Tests ---

def test_cli_analyze_face_libs_missing(mock_face_libs_unavailable):
    """Tests that the CLI command exits if face libraries are missing."""
    result = runner.invoke(biomint_app, ["analyze-face", "dummy.jpg"])
    assert result.exit_code == 1
    assert "Error: 'face_recognition' and 'opencv-python' libraries are required." in result.stdout

@patch("chimera_intel.core.biomint.os.path.exists", return_value=True)
def test_analyze_face_image_success(mock_exists, mock_face_libs):
    """Tests successful face detection in an image."""
    mock_cv, mock_fr = mock_face_libs
    
    # Mock return values for face_recognition
    mock_image = np.array([[[1,2,3]]]) # Dummy image data
    mock_fr.load_image_file.return_value = mock_image
    mock_fr.face_locations.return_value = [(10, 50, 60, 20)] # (top, right, bottom, left)

    result = analyze_face("test_image.jpg")

    mock_fr.load_image_file.assert_called_with("test_image.jpg")
    mock_fr.face_locations.assert_called_with(mock_image)
    assert result.error is None
    assert result.faces_found == 1
    assert result.face_locations[0] == {"top": 10, "right": 50, "bottom": 60, "left": 20}

@patch("chimera_intel.core.biomint.os.path.exists", return_value=False)
def test_analyze_face_file_not_found(mock_exists, mock_face_libs):
    """Tests face analysis when the file is missing."""
    result = analyze_face("nonexistent.jpg")
    assert "File not found" in result.error

# --- Voice Comparison Tests ---

@patch("chimera_intel.core.biomint._extract_features")
@patch("chimera_intel.core.biomint._compare_features")
def test_compare_voices_match(mock_compare, mock_extract):
    """Tests a successful voice match."""
    # Mock features to be non-None
    mock_extract.side_effect = [np.array([[1]]), np.array([[2]])]
    # Mock similarity score to be high
    mock_compare.return_value = 0.95

    result = compare_voices("voice_a.wav", "voice_b.wav", threshold=0.8)

    assert result.error is None
    assert result.similarity_score == 0.95
    assert result.decision == "Match"
    assert mock_extract.call_count == 2
    mock_compare.assert_called_once()

@patch("chimera_intel.core.biomint._extract_features")
@patch("chimera_intel.core.biomint._compare_features")
def test_compare_voices_no_match(mock_compare, mock_extract):
    """Tests when voices do not match (low similarity)."""
    mock_extract.side_effect = [np.array([[1]]), np.array([[2]])]
    # Mock similarity score to be low
    mock_compare.return_value = 0.5

    result = compare_voices("voice_a.wav", "voice_b.wav", threshold=0.8)

    assert result.error is None
    assert result.similarity_score == 0.50
    assert result.decision == "No Match"

@patch("chimera_intel.core.biomint._extract_features", return_value=None)
def test_compare_voices_extract_error(mock_extract):
    """Tests failure when feature extraction returns None."""
    result = compare_voices("voice_a.wav", "voice_b.wav")
    assert "Could not extract features" in result.error

@patch("chimera_intel.core.biomint.compare_voices")
def test_cli_compare_voices_match(mock_compare):
    """Tests the CLI command for a voice match."""
    mock_compare.return_value = MagicMock(
        decision="Match", 
        similarity_score=0.9,
        model_dump=lambda: {"decision": "Match", "similarity_score": 0.9} # Mock model_dump
    )

    result = runner.invoke(biomint_app, ["compare-voices", "a.wav", "b.wav", "-t", "0.7"])
    
    assert result.exit_code == 0
    assert "VOICE MATCH FOUND!" in result.stdout
    assert "(Similarity: 0.9)" in result.stdout
    mock_compare.assert_called_with("a.wav", "b.wav", 0.7)