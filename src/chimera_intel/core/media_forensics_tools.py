"""
Advanced Media Forensics Tools Integration
This module integrates various media forensics tools such as ExifTool,
FFmpeg, Error Level Analysis (ELA), and deep learning model loaders for
media analysis."""
import subprocess
import json
import os
import shutil
import logging
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from PIL import Image, ImageChops, ImageEnhance
import cv2
import numpy as np
# --- InVID-related Additions ---
from scenedetect import open_video, SceneManager, ContentDetector
from skimage.metrics import structural_similarity as ssim
from skimage.restoration import estimate_sigma
import face_recognition
# --- Real DL Model Loader Additions ---
import torch
import torch.nn as nn
from torchvision import transforms
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import typer

# Configure logging
log = logging.getLogger(__name__)

class ToolIntegrationError(Exception):
    """Custom exception for tool integration failures."""
    pass

# --- 1. Metadata Tools (ExifTool, FFmpeg Metadata) ---

class ExifToolWrapper:
    """
    Provides a wrapper for the ExifTool command-line utility
    to extract comprehensive metadata from media files.
    """
    def __init__(self, exiftool_path: str = "exiftool"):
        self.exiftool_path = shutil.which(exiftool_path)
        if not self.exiftool_path:
            log.warning("ExifTool not found in system PATH. Metadata inspection will be unavailable.")
            raise ToolIntegrationError("ExifTool executable not found.")

    def get_metadata(self, file_path: str) -> Dict[str, Any]:
        """
        Extracts metadata from a file as a JSON object.
        """
        if not os.path.exists(file_path):
            log.error(f"File not found for ExifTool analysis: {file_path}")
            return {"Error": "File not found."}
        try:
            command = [self.exiftool_path, "-j", "-G", file_path]
            result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')
            metadata = json.loads(result.stdout)
            return metadata[0] if metadata else {"Error": "No metadata extracted."}
        except Exception as e:
            log.error(f"An unexpected error occurred with ExifTool: {e}")
            return {"Error": "An unexpected error occurred.", "Details": str(e)}

class FFmpegWrapper:
    """
    Provides a wrapper for FFmpeg/FFprobe to analyze video, get metadata,
    and extract various types of frames (InVID features 1 & 2).
    """
    def __init__(self, ffmpeg_path: str = "ffmpeg", ffprobe_path: str = "ffprobe"):
        self.ffmpeg_path = shutil.which(ffmpeg_path)
        self.ffprobe_path = shutil.which(ffprobe_path)
        if not self.ffmpeg_path or not self.ffprobe_path:
            log.warning("FFmpeg or FFprobe not found in PATH. Video analysis will be unavailable.")
            raise ToolIntegrationError("FFmpeg/FFprobe executables not found.")

    def get_video_metadata(self, video_path: str) -> Dict[str, Any]:
        """
        Uses FFprobe to get detailed format and stream metadata (InVID feature 2).
        """
        try:
            command = [
                self.ffprobe_path, "-v", "quiet", "-print_format", "json",
                "-show_format", "-show_streams", video_path
            ]
            result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')
            return json.loads(result.stdout)
        except Exception as e:
            log.error(f"FFprobe failed for {video_path}: {e}")
            return {"Error": "FFprobe execution failed.", "Details": str(e)}

    def extract_frames_by_rate(self, video_path: str, output_dir: str, frame_rate: int = 1) -> List[str]:
        """
        Extracts frames from a video at a specified rate (e.g., 1 frame per second).
        """
        os.makedirs(output_dir, exist_ok=True)
        output_pattern = os.path.join(output_dir, "frame-%06d.png")
        try:
            command = [
                self.ffmpeg_path, "-i", video_path, "-vf", f"fps={frame_rate}",
                output_pattern
            ]
            subprocess.run(command, capture_output=True, text=True, check=True)
            extracted = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.startswith("frame-")]
            log.info(f"Extracted {len(extracted)} frames to {output_dir}")
            return extracted
        except subprocess.CalledProcessError as e:
            log.error(f"FFmpeg frame extraction failed: {e.stderr}")
            raise ToolIntegrationError(f"FFmpeg failed: {e.stderr}")

    def extract_keyframes(self, video_path: str, output_dir: str) -> List[str]:
        """
        Extracts only the keyframes (I-frames) from a video (InVID feature 1).
        """
        os.makedirs(output_dir, exist_ok=True)
        output_pattern = os.path.join(output_dir, "keyframe-%06d.png")
        try:
            command = [
                self.ffmpeg_path, "-i", video_path, "-vf", "select='eq(pict_type,I)'",
                "-vsync", "vfr", output_pattern
            ]
            subprocess.run(command, capture_output=True, text=True, check=True)
            extracted = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.startswith("keyframe-")]
            log.info(f"Extracted {len(extracted)} keyframes to {output_dir}")
            return extracted
        except subprocess.CalledProcessError as e:
            log.error(f"FFmpeg keyframe extraction failed: {e.stderr}")
            raise ToolIntegrationError(f"FFmpeg failed: {e.stderr}")

    def extract_scene_changes(self, video_path: str, output_dir: str) -> List[str]:
        """
        Uses PySceneDetect to find content-based scene changes and
        save the frame at the start of each new scene (InVID feature 1, advanced).
        """
        try:
            os.makedirs(output_dir, exist_ok=True)
            video = open_video(video_path)
            scene_manager = SceneManager()
            scene_manager.add_detector(ContentDetector())
            scene_manager.detect_scenes(video, show_progress=False)
            scene_list = scene_manager.get_scene_list()
            
            extracted_files = []
            for i, scene in enumerate(scene_list):
                start_frame = scene[0].get_frames()
                frame_img = video.get_frame(start_frame)
                
                output_path = os.path.join(output_dir, f"scene-{i+1:04d}-frame-{start_frame}.png")
                pil_img = Image.fromarray(frame_img)
                pil_img.save(output_path)
                extracted_files.append(output_path)
                
            log.info(f"Extracted {len(extracted_files)} scene changes to {output_dir}")
            return extracted_files
        except Exception as e:
            log.error(f"PySceneDetect failed for {video_path}: {e}")
            raise ToolIntegrationError(f"Scene detection failed: {e}")


# --- 2. Forensic Triage Tools (ELA, Noise, Blur, SSIM) ---

class ELAWrapper:
    """
    Implements local Error Level Analysis (ELA) (InVID feature 6).
    """
    def analyze(self, image_path: str, output_path: str, quality: int = 90, scale: float = 10.0):
        """
        Performs ELA on an image and saves the result.
        """
        try:
            original = Image.open(image_path).convert('RGB')
            temp_resave_path = output_path + ".temp.jpg"
            original.save(temp_resave_path, 'JPEG', quality=quality)
            resaved = Image.open(temp_resave_path)
            
            ela_image = ImageChops.difference(original, resaved)
            enhancer = ImageEnhance.Brightness(ela_image)
            ela_image = enhancer.enhance(scale)
            ela_image.save(output_path)
            os.remove(temp_resave_path)
            log.info(f"ELA analysis saved to {output_path}")
        except Exception as e:
            log.error(f"Failed to perform ELA on {image_path}: {e}")
            if os.path.exists(temp_resave_path):
                os.remove(temp_resave_path)
            raise

class ImageAnalysisWrapper:
    """
    Provides image comparison and triage tools (InVID features 4, 5, 6).
    Uses OpenCV and scikit-image.
    """
    def _load_image(self, image_path: str, mode: str = 'gray') -> np.ndarray:
        """Helper to load image for CV2/skimage."""
        image = cv2.imread(image_path)
        if image is None:
            raise FileNotFoundError(f"Image file not found: {image_path}")
        if mode == 'gray':
            return cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        elif mode == 'color':
            return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        return image # BGR

    def compare_histograms(self, image_path_1: str, image_path_2: str) -> float:
        """
        Compares the color histograms of two images.
        Returns a correlation score (1.0 is perfect match). (InVID feature 4).
        """
        try:
            img1 = self._load_image(image_path_1, 'color')
            img2 = self._load_image(image_path_2, 'color')
            
            hist1 = cv2.calcHist([img1], [0, 1, 2], None, [8, 8, 8], [0, 256, 0, 256, 0, 256])
            cv2.normalize(hist1, hist1, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX)
            hist2 = cv2.calcHist([img2], [0, 1, 2], None, [8, 8, 8], [0, 256, 0, 256, 0, 256])
            cv2.normalize(hist2, hist2, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX)
            
            return cv2.compareHist(hist1, hist2, cv2.HISTCMP_CORREL)
        except Exception as e:
            log.error(f"Histogram comparison failed: {e}")
            return 0.0

    def compare_ssim(self, image_path_1: str, image_path_2: str) -> float:
        """
        Computes the Structural Similarity Index (SSIM) between two images.
        (InVID feature 5).
        """
        try:
            img1 = self._load_image(image_path_1, 'gray')
            img2 = self._load_image(image_path_2, 'gray')
            
            # Resize images to be the same size for comparison
            h, w = img1.shape
            img2_resized = cv2.resize(img2, (w, h))
            
            score, _ = ssim(img1, img2_resized, full=True)
            return score
        except Exception as e:
            log.error(f"SSIM comparison failed: {e}")
            return 0.0

    def calculate_blur(self, image_path: str) -> float:
        """
        Calculates a blur metric using the variance of the Laplacian.
        A low score suggests a high amount of blur. (InVID feature 6).
        """
        try:
            img = self._load_image(image_path, 'gray')
            return cv2.Laplacian(img, cv2.CV_64F).var()
        except Exception as e:
            log.error(f"Blur calculation failed: {e}")
            return 0.0
            
    def calculate_noise(self, image_path: str) -> float:
        """
        Estimates the standard deviation of Gaussian noise in an image.
        (InVID feature 6).
        """
        try:
            img_rgb = self._load_image(image_path, 'color')
            # Estimate noise sigma
            sigma = estimate_sigma(img_rgb, average_sigmas=True, channel_axis=-1)
            return sigma
        except Exception as e:
            log.error(f"Noise calculation failed: {e}")
            return 0.0

# --- 3. External Verification Tools (REMOVED) ---

# class ReverseImageSearchWrapper: ( ... REMOVED ... )
# class SocialMediaVerifier: ( ... REMOVED ... )


# --- 4. Face & Object Analysis Tools (OpenCV, dlib) ---

class FaceAnalysisWrapper:
    """
    A wrapper for face analysis using face_recognition.
    """
    def detect_faces(self, image_path: str) -> List[Tuple[int, int, int, int]]:
        try:
            image = face_recognition.load_image_file(image_path)
            return face_recognition.face_locations(image)
        except Exception as e:
            log.error(f"Face detection failed for {image_path}: {e}")
            return []

    def extract_landmarks(self, image_path: str) -> List[Dict[str, List[Tuple[int, int]]]]:
        try:
            image = face_recognition.load_image_file(image_path)
            return face_recognition.face_landmarks(image)
        except Exception as e:
            log.error(f"Landmark extraction failed for {image_path}: {e}")
            return []

# --- 5. "Real" Deep Learning Model Loaders ---

class SimpleDeepfakeClassifier(nn.Module):
    """
    A very simple CNN for demonstration.
    """
    def __init__(self):
        super(SimpleDeepfakeClassifier, self).__init__()
        self.conv1 = nn.Conv2d(3, 16, 3, padding=1)
        self.pool = nn.MaxPool2d(2, 2)
        self.conv2 = nn.Conv2d(16, 32, 3, padding=1)
        self.fc1 = nn.Linear(32 * 56 * 56, 120) # Assumes 224x224 input
        self.fc2 = nn.Linear(120, 2) # 2 classes: real, fake
        self.relu = nn.ReLU()
        self.log_softmax = nn.LogSoftmax(dim=1)

    def forward(self, x):
        x = self.pool(self.relu(self.conv1(x)))
        x = self.pool(self.relu(self.conv2(x)))
        x = x.view(-1, 32 * 56 * 56)
        x = self.relu(self.fc1(x))
        x = self.log_softmax(self.fc2(x))
        return x

class DLModelLoader:
    """
    A loader for PyTorch/TensorFlow models for tasks
    like deepfake detection, object recognition, etc.
    """
    
    def __init__(self, model_type: str = "pytorch"):
        if model_type not in ["pytorch", "tensorflow"]:
            raise ValueError("model_type must be 'pytorch' or 'tensorflow'")
        self.model_type = model_type
        self.model = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        self.pt_transforms = transforms.Compose([
            transforms.Resize((224, 224)),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
        ])

    def _get_tf_model(self):
        """Helper to define a simple Keras model."""
        return keras.Sequential([
            layers.Resizing(224, 224),
            layers.Rescaling(1./255),
            layers.Conv2D(16, 3, padding='same', activation='relu'),
            layers.MaxPooling2D(),
            layers.Conv2D(32, 3, padding='same', activation='relu'),
            layers.MaxPooling2D(),
            layers.Flatten(),
            layers.Dense(120, activation='relu'),
            layers.Dense(2, activation='softmax') # real, fake
        ])

    def load(self, model_path: str, model_definition: Optional[Any] = None):
        """
        Loads the model weights into memory.
        """
        try:
            if self.model_type == "pytorch":
                if model_definition is None:
                    raise ValueError("PyTorch loading requires a model_definition instance.")
                self.model = model_definition
                self.model.load_state_dict(torch.load(model_path, map_location=self.device))
                self.model.to(self.device)
                self.model.eval()
                log.info(f"PyTorch model weights loaded from {model_path}")
            
            else: # TensorFlow
                if model_path.endswith(".h5"):
                    self.model = keras.models.load_model(model_path)
                    log.info(f"TensorFlow Keras model loaded from {model_path}")
                else:
                    self.model = self._get_tf_model()
                    self.model.load_weights(model_path)
                    log.info(f"TensorFlow weights loaded from {model_path}")
                    
        except Exception as e:
            log.error(f"Failed to load DL model from {model_path}: {e}")
            raise ToolIntegrationError(f"Model loading failed: {e}")

    def predict(self, image_path: str) -> Dict[str, float]:
        """
        Runs inference on a single image.
        """
        if not self.model:
            raise ToolIntegrationError("Model is not loaded. Call .load() first.")
            
        try:
            image = Image.open(image_path).convert("RGB")
            
            if self.model_type == "pytorch":
                tensor = self.pt_transforms(image).unsqueeze(0).to(self.device)
                with torch.no_grad():
                    output = self.model(tensor)
                    probabilities = torch.exp(output).cpu().numpy()[0]
                return {"real": probabilities[0], "fake": probabilities[1]}
                
            else: # TensorFlow
                img_array = tf.keras.utils.img_to_array(image)
                img_batch = tf.expand_dims(img_array, 0)
                output = self.model.predict(img_batch, verbose=0)
                probabilities = output[0]
                return {"real": probabilities[0], "fake": probabilities[1]}
                
        except Exception as e:
            log.error(f"Prediction failed for {image_path}: {e}")
            raise ToolIntegrationError(f"Prediction failed: {e}")


# =======================================================================
# ==                 CLI Application (Merged)                          ==
# =======================================================================

app = typer.Typer(
    name="media-tools",
    help="CLI for advanced media forensics tools (ExifTool, ELA, FFmpeg, etc.)"
)

# Helper to load a tool and handle its absence
def load_tool(tool_class):
    try:
        return tool_class()
    except ToolIntegrationError as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    except Exception as e:
        typer.secho(f"Error: Could not initialize {tool_class.__name__}. Dependencies may be missing: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

@app.command(name="exif")
def cli_exif(
    file: Path = typer.Argument(..., exists=True, readable=True, help="Path to the media file.")
):
    """
    Extracts all metadata from a file using ExifTool.
    """
    wrapper = load_tool(ExifToolWrapper)
    metadata = wrapper.get_metadata(str(file))
    typer.echo(json.dumps(metadata, indent=2))

@app.command(name="ela")
def cli_ela(
    image: Path = typer.Argument(..., exists=True, readable=True, help="Path to the original image."),
    output: Path = typer.Argument(..., writable=True, help="Path to save the ELA result."),
    quality: int = typer.Option(90, help="JPEG quality for re-saving."),
    scale: float = typer.Option(10.0, help="Brightness enhancement scale.")
):
    """
    Performs Error Level Analysis (ELA) on an image.
    """
    wrapper = load_tool(ELAWrapper)
    try:
        wrapper.analyze(str(image), str(output), quality=quality, scale=scale)
        typer.secho(f"ELA image saved to: {output}", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"ELA analysis failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

@app.command(name="ffmpeg-metadata")
def cli_ffmpeg_meta(
    video: Path = typer.Argument(..., exists=True, readable=True, help="Path to the video file.")
):
    """
    Extracts video/stream metadata using FFprobe.
    """
    wrapper = load_tool(FFmpegWrapper)
    metadata = wrapper.get_video_metadata(str(video))
    typer.echo(json.dumps(metadata, indent=2))

@app.command(name="ffmpeg-frames")
def cli_ffmpeg_frames(
    video: Path = typer.Argument(..., exists=True, readable=True, help="Path to the video file."),
    output_dir: Path = typer.Argument(..., file_okay=False, writable=True, help="Directory to save frames."),
    rate: int = typer.Option(1, help="Frames per second to extract.")
):
    """
    Extracts frames from a video at a given rate.
    """
    wrapper = load_tool(FFmpegWrapper)
    try:
        os.makedirs(str(output_dir), exist_ok=True)
        files = wrapper.extract_frames_by_rate(str(video), str(output_dir), frame_rate=rate)
        typer.secho(f"Extracted {len(files)} frames to {output_dir}", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"Frame extraction failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

@app.command(name="find-faces")
def cli_find_faces(
    image: Path = typer.Argument(..., exists=True, readable=True, help="Path to the image.")
):
    """
    Detects faces in an image and returns their locations.
    """
    wrapper = load_tool(FaceAnalysisWrapper)
    locations = wrapper.detect_faces(str(image))
    if not locations:
        typer.secho("No faces found.", fg=typer.colors.YELLOW)
        return
    typer.secho(f"Found {len(locations)} face(s):", fg=typer.colors.GREEN)
    for loc in locations:
        typer.echo(f"- Location (top, right, bottom, left): {loc}")

@app.command(name="ssim")
def cli_ssim(
    image1: Path = typer.Argument(..., exists=True, readable=True, help="Path to the first image."),
    image2: Path = typer.Argument(..., exists=True, readable=True, help="Path to the second image.")
):
    """
    Calculates the Structural Similarity (SSIM) between two images.
    """
    wrapper = load_tool(ImageAnalysisWrapper)
    try:
        score = wrapper.compare_ssim(str(image1), str(image2))
        typer.secho(f"SSIM Score: {score:.4f} (1.0 is identical)", fg=typer.colors.CYAN)
    except Exception as e:
        typer.secho(f"SSIM calculation failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)