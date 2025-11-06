# Tests/test_media_forensics_tools.py

import pytest
import subprocess
import json
from unittest.mock import MagicMock, patch, call
import os
import numpy as np
from PIL import Image
import torch
import tensorflow as tf
from typer.testing import CliRunner

# Import the new classes from the core module
from src.chimera_intel.core.media_forensics_tools import (
    ExifToolWrapper,
    ELAWrapper,
    FFmpegWrapper,
    FaceAnalysisWrapper,
    ImageAnalysisWrapper,
    # SocialMediaVerifier, # <-- REMOVED
    DLModelLoader,
    SimpleDeepfakeClassifier,
    ToolIntegrationError,
    app as cli_app  # Import the CLI app from its new location
)

# ---- Fixtures ----

@pytest.fixture
def mock_subprocess_run(mocker):
    """Fixture to mock subprocess.run."""
    return mocker.patch('subprocess.run')

@pytest.fixture
def mock_shutil_which(mocker):
    """Fixture to mock shutil.which, pretending tools are found."""
    mock_which = mocker.patch('shutil.which')
    mock_which.side_effect = lambda cmd: f"/usr/bin/{cmd}"
    return mock_which

@pytest.fixture
def tmp_image_pair(tmp_path):
    """Create two dummy images for comparison testing."""
    img1_path = tmp_path / "image1.png"
    img2_path = tmp_path / "image2.png"
    img1 = Image.new('RGB', (100, 100), color = 'red')
    img1.save(img1_path)
    img2 = Image.new('RGB', (100, 100), color = 'blue')
    img2.save(img2_path)
    return str(img1_path), str(img2_path)

# @pytest.fixture
# def mock_requests(mocker):  # <-- REMOVED
#     ...

@pytest.fixture
def runner():
    """Fixture for testing the Typer CLI app."""
    return CliRunner()

# ---- Test Cases for Tool Wrappers ----

class TestFFmpegWrapper:

    def test_extract_keyframes(self, mock_shutil_which, mock_subprocess_run, tmp_path):
        video_path = tmp_path / "test.mp4"
        output_dir = tmp_path / "frames"
        
        with patch('os.listdir', return_value=["keyframe-000001.png"]):
            wrapper = FFmpegWrapper()
            files = wrapper.extract_keyframes(str(video_path), str(output_dir))
        
        expected_call = [
            wrapper.ffmpeg_path, "-i", str(video_path),
            "-vf", "select='eq(pict_type,I)'", "-vsync", "vfr",
            os.path.join(output_dir, "keyframe-%06d.png")
        ]
        mock_subprocess_run.assert_called_once_with(
            expected_call, capture_output=True, text=True, check=True
        )
        assert len(files) == 1

    @patch('src.chimera_intel.core.media_forensics_tools.open_video')
    @patch('src.chimera_intel.core.media_forensics_tools.SceneManager')
    def test_extract_scene_changes(self, mock_scene_manager_cls, mock_open_video, tmp_path):
        video_path = tmp_path / "test.mp4"
        output_dir = tmp_path / "scenes"
        
        mock_video = MagicMock()
        mock_open_video.return_value = mock_video
        mock_scene_manager = MagicMock()
        mock_scene_manager_cls.return_value = mock_scene_manager
        mock_frame_timecode = MagicMock()
        mock_frame_timecode.get_frames.return_value = 150
        mock_scene_manager.get_scene_list.return_value = [(mock_frame_timecode, MagicMock())]
        mock_video.get_frame.return_value = np.zeros((100, 100, 3), dtype=np.uint8)
        
        wrapper = FFmpegWrapper()
        files = wrapper.extract_scene_changes(str(video_path), str(output_dir))
        
        mock_open_video.assert_called_once_with(str(video_path))
        mock_scene_manager.detect_scenes.assert_called_once_with(mock_video, show_progress=False)
        assert len(files) == 1

class TestImageAnalysisWrapper:

    def test_compare_ssim(self, tmp_image_pair):
        img1_path, img2_path = tmp_image_pair
        wrapper = ImageAnalysisWrapper()
        score_self = wrapper.compare_ssim(img1_path, img1_path)
        assert score_self == pytest.approx(1.0)
        score_diff = wrapper.compare_ssim(img1_path, img2_path)
        assert score_diff < 0.1

# class TestSocialMediaVerifier: ( ... REMOVED ... )

class TestDLModelLoader:

    def test_pytorch_predict_e2e(self, tmp_image_pair):
        img_path, _ = tmp_image_pair
        loader = DLModelLoader(model_type="pytorch")
        real_model = SimpleDeepfakeClassifier()
        mock_output = torch.tensor([[-0.1, -2.3]]) # LogSoftmax output
        
        with patch.object(real_model, 'forward', return_value=mock_output) as mock_forward:
            loader.model = real_model
            loader.model.eval()
            loader.model.to(loader.device)
            result = loader.predict(img_path)
            mock_forward.assert_called_once()
            input_tensor = mock_forward.call_args[0][0]
            assert input_tensor.shape == (1, 3, 224, 224)
            assert result["real"] == pytest.approx(torch.exp(mock_output)[0][0].item())

    def test_tensorflow_predict_e2e(self, tmp_image_pair):
        img_path, _ = tmp_image_pair
        mock_tf_model = MagicMock()
        mock_tf_model.predict = MagicMock(return_value=np.array([[0.1, 0.9]]))
        
        loader = DLModelLoader(model_type="tensorflow")
        loader.model = mock_tf_model
        result = loader.predict(img_path)
        mock_tf_model.predict.assert_called_once()
        input_batch = mock_tf_model.predict.call_args[0][0]
        assert input_batch.shape == (1, 100, 100, 3)
        assert result == {"real": 0.1, "fake": 0.9}

# ---- Test Cases for CLI ----

@patch('src.chimera_intel.core.media_forensics_tools.ExifToolWrapper')
def test_cli_exif(mock_exif_wrapper_cls, runner, tmp_path):
    """Tests the 'media-tools exif' command."""
    mock_wrapper = MagicMock()
    mock_wrapper.get_metadata.return_value = {"Make": "Canon"}
    mock_exif_wrapper_cls.return_value = mock_wrapper
    
    test_file = tmp_path / "test.jpg"
    test_file.touch()
    
    result = runner.invoke(cli_app, ["exif", str(test_file)])
    
    assert result.exit_code == 0
    mock_wrapper.get_metadata.assert_called_once_with(str(test_file))
    assert '"Make": "Canon"' in result.stdout

@patch('src.chimera_intel.core.media_forensics_tools.ELAWrapper')
def test_cli_ela(mock_ela_wrapper_cls, runner, tmp_path):
    """Tests the 'media-tools ela' command."""
    mock_wrapper = MagicMock()
    mock_ela_wrapper_cls.return_value = mock_wrapper
    
    img_file = tmp_path / "test.png"
    Image.new('RGB', (10, 10)).save(img_file)
    out_file = tmp_path / "ela.png"
    
    result = runner.invoke(cli_app, ["ela", str(img_file), str(out_file), "--quality", "85"])
    
    assert result.exit_code == 0
    mock_wrapper.analyze.assert_called_once_with(str(img_file), str(out_file), quality=85, scale=10.0)
    assert "ELA image saved" in result.stdout

@patch('src.chimera_intel.core.media_forensics_tools.FFmpegWrapper')
def test_cli_ffmpeg_metadata(mock_ffmpeg_wrapper_cls, runner, tmp_path):
    """Tests the 'media-tools ffmpeg-metadata' command."""
    mock_wrapper = MagicMock()
    mock_wrapper.get_video_metadata.return_value = {"format": {"duration": "10.0"}}
    mock_ffmpeg_wrapper_cls.return_value = mock_wrapper
    
    test_file = tmp_path / "test.mp4"
    test_file.touch()
    
    result = runner.invoke(cli_app, ["ffmpeg-metadata", str(test_file)])
    
    assert result.exit_code == 0
    mock_wrapper.get_video_metadata.assert_called_once_with(str(test_file))
    assert '"duration": "10.0"' in result.stdout

@patch('src.chimera_intel.core.media_forensics_tools.ImageAnalysisWrapper')
def test_cli_ssim(mock_img_analysis_cls, runner, tmp_image_pair):
    """Tests the 'media-tools ssim' command."""
    img1, img2 = tmp_image_pair
    mock_wrapper = MagicMock()
    mock_wrapper.compare_ssim.return_value = 0.9876
    mock_img_analysis_cls.return_value = mock_wrapper
    
    result = runner.invoke(cli_app, ["ssim", img1, img2])
    
    assert result.exit_code == 0
    mock_wrapper.compare_ssim.assert_called_once_with(img1, img2)
    assert "SSIM Score: 0.9876" in result.stdout

@patch('src.chimera_intel.core.media_forensics_tools.FaceAnalysisWrapper')
def test_cli_find_faces(mock_face_analysis_cls, runner, tmp_image_pair):
    """Tests the 'media-tools find-faces' command."""
    img1, _ = tmp_image_pair
    mock_wrapper = MagicMock()
    mock_wrapper.detect_faces.return_value = [(10, 60, 50, 20)]
    mock_face_analysis_cls.return_value = mock_wrapper
    
    result = runner.invoke(cli_app, ["find-faces", img1])
    
    assert result.exit_code == 0
    mock_wrapper.detect_faces.assert_called_once_with(img1)
    assert "Found 1 face(s)" in result.stdout
    assert "(10, 60, 50, 20)" in result.stdout