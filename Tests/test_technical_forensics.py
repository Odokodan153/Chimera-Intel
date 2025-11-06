import pytest
import numpy as np
import cv2
from PIL import Image
from pathlib import Path
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# Module to test
from chimera_intel.core.technical_forensics import (
    cli_app,
    TechnicalImageAnalyzer,
    TechnicalVideoAnalyzer
)

runner = CliRunner()

# --- Fixtures ---

@pytest.fixture(scope="module")
def sample_image(tmp_path_factory):
    """Create a dummy image with a face."""
    tmp_path = tmp_path_factory.mktemp("test_images")
    file_path = tmp_path / "test_face.png"
    
    # Create a 200x200 image
    img = np.zeros((200, 200, 3), dtype=np.uint8)
    
    # Draw a "face"
    cv2.rectangle(img, (50, 50), (150, 150), (200, 200, 200), -1) # Face
    # Make top-left quadrant brighter
    img[50:100, 50:100] = [250, 250, 250]
    
    # Draw "eyes"
    cv2.circle(img, (80, 80), 5, (0, 0, 255), -1) # Left eye (blue)
    cv2.circle(img, (120, 80), 5, (0, 255, 0), -1) # Right eye (green) - Mismatch!
    
    # Draw "lines" for perspective
    cv2.line(img, (10, 10), (190, 10), (255, 255, 255), 2)
    cv2.line(img, (10, 190), (190, 190), (255, 255, 255), 2)
    
    cv2.imwrite(str(file_path), img)
    return str(file_path)

@pytest.fixture(scope="module")
def aberration_image(tmp_path_factory):
    """Create an image with high chromatic aberration."""
    tmp_path = tmp_path_factory.mktemp("test_images")
    file_path = tmp_path / "test_aberration.png"
    
    img = np.zeros((100, 100, 3), dtype=np.uint8)
    # White square on black background
    img[20:80, 20:80] = [255, 255, 255]
    
    b, g, r = cv2.split(img)
    
    # Shift R and B channels to create misalignment
    M_r = np.float32([[1, 0, 1], [0, 1, 0]])
    M_b = np.float32([[1, 0, -1], [0, 1, 0]])
    r_shifted = cv2.warpAffine(r, M_r, (100, 100))
    b_shifted = cv2.warpAffine(b, M_b, (100, 100))
    
    final_img = cv2.merge([b_shifted, g, r_shifted])
    cv2.imwrite(str(file_path), final_img)
    return str(file_path)

@pytest.fixture
def mock_dependencies(mocker):
    """Mock heavy libraries like face_recognition and librosa."""
    
    # Mock face_recognition
    mock_fr = MagicMock()
    
    # Mock landmarks for eye analysis
    mock_landmarks = {
        'left_eye': [(70, 80), (75, 78), (80, 80), (85, 78), (80, 82), (75, 82)],
        'right_eye': [(110, 80), (115, 78), (120, 80), (125, 78), (120, 82), (115, 82)],
        'top_lip': [(80, 120), (100, 118), (120, 120)],
        'bottom_lip': [(80, 130), (100, 132), (120, 130)],
    }
    mock_fr.face_landmarks.return_value = [mock_landmarks]
    
    mocker.patch('chimera_intel.core.technical_forensics.face_recognition', mock_fr)
    
    # Mock librosa
    mock_librosa = MagicMock()
    # Create two perfectly correlated signals
    mock_audio_data = np.sin(np.linspace(0, 10 * np.pi, 2 * 30))
    mock_librosa.load.return_value = (mock_audio_data, 22050)
    mock_librosa.resample.return_value = mock_audio_data
    mock_librosa.feature.rms.return_value = [np.abs(mock_audio_data)]
    
    mocker.patch('chimera_intel.core.technical_forensics.librosa', mock_librosa)
    
    # Mock cv2.VideoCapture for lip sync
    mock_cap = MagicMock()
    mock_cap.get.return_value = 30.0 # FPS
    mock_cap.isOpened.return_value = True
    
    # Create frames that match the audio signal
    frames = []
    for i in range(len(mock_audio_data)):
        frame = np.zeros((100, 100, 3), dtype=np.uint8)
        # Add a "mouth" that opens and closes with the sine wave
        # This is hacky but simulates the mouth_opening list
        frames.append((True, frame))
    frames.append((False, None)) # End of video
    
    mock_cap.read.side_effect = frames
    mocker.patch('cv2.VideoCapture', return_value=mock_cap)
    
    return mock_fr, mock_librosa, mock_cap

# --- Test Cases ---

def test_lighting_analysis(sample_image, mock_dependencies):
    """Test the lighting quadrant heuristic."""
    analyzer = TechnicalImageAnalyzer(sample_image)
    result = analyzer.analyze_lighting_shadows()
    
    assert result.status == "completed"
    assert result.brightest_quadrant == "top_left"
    assert result.brightness_map["top_left"] > 240
    assert result.brightness_map["bottom_right"] < 210

def test_perspective_analysis(sample_image, mock_dependencies):
    """Test the line detection heuristic."""
    analyzer = TechnicalImageAnalyzer(sample_image)
    result = analyzer.analyze_perspective()
    
    assert result.status == "completed"
    assert result.detected_lines > 0
    # Should find horizontal lines (0 and 180/-180 degrees)
    assert any(angle[0] == -10 or angle[0] == 0 for angle in result.dominant_angles)

def test_chromatic_aberration(aberration_image, sample_image, mock_dependencies):
    """Test aberration detection."""
    # Test on the bad image
    analyzer_bad = TechnicalImageAnalyzer(aberration_image)
    result_bad = analyzer_bad.analyze_chromatic_aberration()
    
    assert result_bad.status == "completed"
    assert result_bad.is_suspicious == True
    assert result_bad.aberration_score > 10.0
    
    # Test on the good image
    analyzer_good = TechnicalImageAnalyzer(sample_image)
    result_good = analyzer_good.analyze_chromatic_aberration()
    
    assert result_good.status == "completed"
    assert result_good.is_suspicious == False

def test_eye_reflection(sample_image, mock_dependencies):
    """Test eye reflection comparison."""
    mock_fr, _, _ = mock_dependencies
    analyzer = TechnicalImageAnalyzer(sample_image)
    result = analyzer.analyze_eye_reflections()
    
    mock_fr.face_landmarks.assert_called_once()
    assert result.status == "completed"
    # Our fixture image has different colored eyes, so correlation should be low
    assert result.is_suspicious == True
    assert result.histogram_correlation < 0.8 

def test_lip_sync(sample_image, mock_dependencies):
    """Test lip sync correlation. (sample_image is just a placeholder path)."""
    mock_fr, mock_librosa, mock_cap = mock_dependencies
    
    # Manually adjust mock to create matching mouth openings
    # The 'mock_audio_data' is a sine wave.
    mock_audio_data = np.sin(np.linspace(0, 10 * np.pi, 2 * 30))
    # We need to simulate the landmark detection finding a mouth that
    # opens and closes with this same sine wave.
    
    def mock_face_landmarks_sync(frame):
        # We cheat and use the audio data to set the lip distance
        frame_num = int(mock_cap.get(cv2.CAP_PROP_POS_FRAMES))
        if frame_num >= len(mock_audio_data):
            return []
            
        # Get the "opening" from the audio data
        opening = (mock_audio_data[frame_num] + 1) * 5 # Scale from [-1, 1] to [0, 10]
        
        return [{
            'top_lip': [(10, 20)],
            'bottom_lip': [(10, 20 + opening)] # Set distance
        }]
    
    mock_fr.face_landmarks = mock_face_landmarks_sync
    mock_cap.get.side_effect = [30.0] + list(range(len(mock_audio_data) + 1)) # FPS then frame numbers

    analyzer = TechnicalVideoAnalyzer(sample_image)
    result = analyzer.analyze_lip_sync()
    
    assert result.status == "completed"
    # Correlation should be very high (near 1.0)
    assert result.is_suspicious == False
    assert result.correlation_score > 0.9

def test_cli_all_command(sample_image, mock_dependencies):
    """Test the main 'all' CLI command."""
    result = runner.invoke(cli_app, ["all", sample_image])
    assert result.exit_code == 0
    assert "Lighting Analysis" in result.stdout
    assert "Perspective Analysis" in result.stdout
    assert "Aberration Analysis" in result.stdout
    assert "Eye Reflection Analysis" in result.stdout
    # Is an image, so lip sync should not run
    assert "Lip Sync Analysis" not in result.stdout