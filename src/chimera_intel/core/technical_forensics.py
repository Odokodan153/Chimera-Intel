"""
Chimera-Intel: Technical Media Forensics Module
===============================================

This module provides advanced, heuristic-based technical forensic analysis
for images and videos. It implements analyses requested by the user that
are not already present in other modules.

Features:
- Lighting & Shadow Inconsistency
- Perspective & Geometry Anomaly Detection
- Chromatic Aberration Heuristics
- Face & Eye Reflection Comparison
- Audio/Video Lip Sync Correlation

This module requires 'face_recognition' and 'librosa'.
pip install dlib face_recognition librosa
"""

import typer
import logging
import cv2
import numpy as np
import librosa
import math
from pathlib import Path
from PIL import Image
from rich.console import Console
from rich.table import Table
try:
    import face_recognition
except ImportError:
    face_recognition = None
from .schemas import (
    LightingAnalysisResult,
    PerspectiveAnalysisResult,
    AberrationAnalysisResult,
    EyeReflectionResult,
    LipSyncResult,
)

# --- Setup ---
logger = logging.getLogger(__name__)
console = Console()

cli_app = typer.Typer(
    name="tech-forensics",
    help="Run advanced technical forensic analyses (lighting, perspective, sync)."
)

def _load_dependencies():
    """Checks for heavy dependencies."""
    if face_recognition is None:
        console.print("[bold red]Error:[/bold red] 'face_recognition' library not found.")
        console.print("Please run: [cyan]pip install dlib face_recognition[/cyan]")
        raise typer.Exit(code=1)
    if not (Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml").exists():
        console.print("[bold red]Error:[/bold red] OpenCV haarcascades not found. Please reinstall opencv-python.")
        raise typer.Exit(code=1)

# -----------------------------------------------------------------
#
# A. Core Analysis Logic Classes
#
# -----------------------------------------------------------------

class TechnicalImageAnalyzer:
    """Performs advanced forensic analysis on static images."""

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        
        try:
            self.pil_image = Image.open(self.file_path).convert("RGB")
            self.cv2_image = cv2.cvtColor(np.array(self.pil_image), cv2.COLOR_RGB2BGR)
            self.gray_image = cv2.cvtColor(self.cv2_image, cv2.COLOR_BGR2GRAY)
        except Exception as e:
            raise IOError(f"Failed to load image {self.file_path}: {e}")
            
        _load_dependencies()
        
    def analyze_lighting_shadows(self) -> LightingAnalysisResult:
        """
        Analyzes dominant light direction based on face shading.
        A simple heuristic: compares brightness of facial quadrants.
        """
        face_cascade = cv2.CascadeClassifier(
            str(Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml")
        )
        faces = face_cascade.detectMultiScale(self.gray_image, 1.1, 4)
        
        if len(faces) == 0:
            return LightingAnalysisResult(
                status="no_faces_found",
                analysis="Could not find faces to analyze lighting."
            )
        
        # Use the largest face
        (x, y, w, h) = sorted(faces, key=lambda f: f[2] * f[3], reverse=True)[0]
        face_roi = self.gray_image[y:y+h, x:x+w]
        
        # Divide face into quadrants
        h_mid, w_mid = h // 2, w // 2
        quadrants = {
            "top_left": face_roi[0:h_mid, 0:w_mid],
            "top_right": face_roi[0:h_mid, w_mid:w],
            "bottom_left": face_roi[h_mid:h, 0:w_mid],
            "bottom_right": face_roi[h_mid:h, w_mid:w],
        }
        
        mean_brightness = {name: np.mean(q) for name, q in quadrants.items() if q.size > 0}
        
        if not mean_brightness:
            return LightingAnalysisResult(status="error", error="Face ROI was empty.")

        sorted_quadrants = sorted(mean_brightness.items(), key=lambda item: item[1])
        darkest = sorted_quadrants[0]
        brightest = sorted_quadrants[-1]
        
        analysis = (
            f"Dominant light appears to come from {brightest[0].replace('_', ' ')} "
            f"(Brightness: {brightest[1]:.2f}), "
            f"with darkest region at {darkest[0].replace('_', ' ')} "
            f"(Brightness: {darkest[1]:.2f})."
        )
        
        return LightingAnalysisResult(
            status="completed",
            brightest_quadrant=brightest[0],
            darkest_quadrant=darkest[0],
            brightness_map=mean_brightness,
            analysis=analysis
        )

    def analyze_perspective(self) -> PerspectiveAnalysisResult:
        """
        Detects dominant lines to infer perspective.
        Inconsistent line angles can indicate a composite.
        """
        # Canny edge detection
        edges = cv2.Canny(self.gray_image, 50, 150, apertureSize=3)
        
        # Hough line transform
        lines = cv2.HoughLinesP(edges, 1, np.pi / 180, threshold=100, minLineLength=50, maxLineGap=10)
        
        if lines is None:
            return PerspectiveAnalysisResult(
                status="no_lines_found",
                detected_lines=0
            )
            
        angles = []
        for line in lines:
            x1, y1, x2, y2 = line[0]
            angle = math.degrees(math.atan2(y2 - y1, x2 - x1))
            angles.append(angle)
            
        # Cluster angles (e.g., into 10-degree bins)
        hist, _ = np.histogram(angles, bins=18, range=(-180, 180))
        dominant_angles = [
            (i * 10 - 180, count) for i, count in enumerate(hist) if count > 0
        ]
        
        return PerspectiveAnalysisResult(
            status="completed",
            detected_lines=len(lines),
            dominant_angles=dominant_angles
        )

    def analyze_chromatic_aberration(self) -> AberrationAnalysisResult:
        """
        Analyzes misalignment between R, G, B color channels at edges.
        High misalignment can indicate compositing or lens artifacts.
        """
        b, g, r = cv2.split(self.cv2_image)
        
        # Use Sobel edge detection on each channel
        sobel_b = cv2.Sobel(b, cv2.CV_64F, 1, 1, ksize=5)
        sobel_g = cv2.Sobel(g, cv2.CV_64F, 1, 1, ksize=5)
        sobel_r = cv2.Sobel(r, cv2.CV_64F, 1, 1, ksize=5)
        
        # Calculate differences between edge maps
        diff_rg = cv2.absdiff(sobel_r, sobel_g)
        diff_gb = cv2.absdiff(sobel_g, sobel_b)
        
        # Score is the mean of the differences
        score_rg = np.mean(diff_rg)
        score_gb = np.mean(diff_gb)
        total_score = (score_rg + score_gb) / 2
        
        is_suspicious = total_score > 10.0 # Empirical threshold
        
        return AberrationAnalysisResult(
            status="completed",
            aberration_score=round(total_score, 4),
            is_suspicious=is_suspicious,
            details=f"R-G diff: {score_rg:.2f}, G-B diff: {score_gb:.2f}"
        )

    def analyze_eye_reflections(self) -> EyeReflectionResult:
        """
        Finds eyes and compares their reflections via histograms.
        Mismatched reflections are a strong indicator of manipulation.
        """
        face_landmarks_list = face_recognition.face_landmarks(self.cv2_image)
        
        if not face_landmarks_list:
            return EyeReflectionResult(status="no_faces_found")
            
        # Use the first face
        landmarks = face_landmarks_list[0]
        
        try:
            # 1. Get eye regions
            left_eye_pts = np.array(landmarks['left_eye'], dtype=np.int32)
            right_eye_pts = np.array(landmarks['right_eye'], dtype=np.int32)
            
            # 2. Crop eye regions
            l_x, l_y, l_w, l_h = cv2.boundingRect(left_eye_pts)
            left_eye_crop = self.gray_image[l_y:l_y+l_h, l_x:l_x+l_w]
            
            r_x, r_y, r_w, r_h = cv2.boundingRect(right_eye_pts)
            right_eye_crop = self.gray_image[r_y:r_y+r_h, r_x:r_x+r_w]

            if left_eye_crop.size == 0 or right_eye_crop.size == 0:
                return EyeReflectionResult(status="error", error="Could not crop eye regions.")

            # 3. Calculate histograms
            left_hist = cv2.calcHist([left_eye_crop], [0], None, [256], [0, 256])
            right_hist = cv2.calcHist([right_eye_crop], [0], None, [256], [0, 256])
            
            cv2.normalize(left_hist, left_hist, 0, 1, cv2.NORM_MINMAX)
            cv2.normalize(right_hist, right_hist, 0, 1, cv2.NORM_MINMAX)
            
            # 4. Compare histograms
            correlation = cv2.compareHist(left_hist, right_hist, cv2.HISTCMP_CORREL)
            
            is_suspicious = correlation < 0.8 # Empirical threshold
            
            return EyeReflectionResult(
                status="completed",
                histogram_correlation=round(correlation, 4),
                is_suspicious=is_suspicious
            )
            
        except Exception as e:
            return EyeReflectionResult(status="error", error=f"Failed during analysis: {e}")


class TechnicalVideoAnalyzer:
    """Performs advanced forensic analysis on videos, focusing on sync."""

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        
        _load_dependencies()
        
    def analyze_lip_sync(self) -> LipSyncResult:
        """
        Correlates audio energy with mouth movement (lip distance)
        to detect audio/video synchronization issues.
        """
        try:
            # 1. Load video and get FPS
            cap = cv2.VideoCapture(str(self.file_path))
            if not cap.isOpened():
                return LipSyncResult(status="error", error="Could not open video file.")
            
            fps = cap.get(cv2.CAP_PROP_FPS)
            if fps == 0:
                return LipSyncResult(status="error", error="Video file has zero FPS.")

            # 2. Load and resample audio
            y, sr = librosa.load(str(self.file_path), sr=None)
            
            # Resample audio to match video frame rate
            y_resampled = librosa.resample(y, orig_sr=sr, target_sr=fps)
            
            # Get audio energy (RMS)
            audio_energy = librosa.feature.rms(y=y_resampled)[0]
            
            # 3. Process video frames for mouth opening
            mouth_openings = []
            frame_count = 0
            while cap.isOpened():
                ret, frame = cap.read()
                if not ret:
                    break
                
                # Resize for faster processing
                small_frame = cv2.resize(frame, (0, 0), fx=0.5, fy=0.5)
                
                # Find face landmarks
                face_landmarks_list = face_recognition.face_landmarks(small_frame)
                
                if face_landmarks_list:
                    landmarks = face_landmarks_list[0]
                    # Get lip points
                    top_lip_pts = landmarks['top_lip']
                    bottom_lip_pts = landmarks['bottom_lip']
                    
                    # Calculate mean vertical position of lips
                    top_lip_mean = np.mean([p[1] for p in top_lip_pts])
                    bottom_lip_mean = np.mean([p[1] for p in bottom_lip_pts])
                    
                    # Distance is the mouth opening
                    distance = abs(top_lip_mean - bottom_lip_mean)
                    mouth_openings.append(distance)
                else:
                    mouth_openings.append(0) # No face, no opening
                
                frame_count += 1
                
                # Stop if audio is shorter (common)
                if frame_count >= len(audio_energy):
                    break
                    
            cap.release()

            # 4. Correlate the two time series
            # Truncate to the shorter of the two signals
            max_len = min(len(audio_energy), len(mouth_openings))
            if max_len < 10: # Not enough data
                return LipSyncResult(status="error", error="Not enough audio/video data to correlate.")
                
            audio_series = audio_energy[:max_len]
            video_series = mouth_openings[:max_len]
            
            # Normalize both signals
            audio_series = (audio_series - np.mean(audio_series)) / (np.std(audio_series) + 1e-6)
            video_series = (video_series - np.mean(video_series)) / (np.std(video_series) + 1e-6)
            
            # Calculate correlation
            correlation_matrix = np.corrcoef(audio_series, video_series)
            correlation = correlation_matrix[0, 1]
            
            # A low correlation suggests a sync issue or no speech
            # A negative correlation is a strong sync issue
            is_suspicious = correlation < 0.1 
            
            return LipSyncResult(
                status="completed",
                correlation_score=round(correlation, 4),
                is_suspicious=is_suspicious,
                frames_analyzed=max_len
            )

        except Exception as e:
            if "No audio stream" in str(e):
                return LipSyncResult(status="skipped", error="No audio stream found in video.")
            logger.error(f"Lip sync analysis failed: {e}", exc_info=True)
            return LipSyncResult(status="error", error=str(e))


# -----------------------------------------------------------------
#
# B. Re-usable Functions & CLI Commands
# (Also defines the new 'tech-forensics' plugin)
#
# -----------------------------------------------------------------

@cli_app.command("lighting", help="Analyze lighting & shadow consistency on faces.")
def cli_analyze_lighting(
    file_path: str = typer.Argument(..., exists=True, help="Path to the image file.")
):
    """CLI command for analyze_lighting_shadows."""
    try:
        analyzer = TechnicalImageAnalyzer(file_path)
        result = analyzer.analyze_lighting_shadows()
        
        console.print(f"[bold]Lighting Analysis:[/bold] {result.status}")
        if result.status == "completed":
            console.print(result.analysis)
            console.print(result.brightness_map)
        else:
            console.print(f"[yellow]{result.error or result.analysis}[/yellow]")
            
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)

@cli_app.command("perspective", help="Analyze perspective lines for inconsistencies.")
def cli_analyze_perspective(
    file_path: str = typer.Argument(..., exists=True, help="Path to the image file.")
):
    """CLI command for analyze_perspective."""
    try:
        analyzer = TechnicalImageAnalyzer(file_path)
        result = analyzer.analyze_perspective()
        
        console.print(f"[bold]Perspective Analysis:[/bold] {result.status}")
        if result.status == "completed":
            console.print(f"Found {result.detected_lines} dominant lines.")
            table = Table("Angle Bin (degrees)", "Line Count")
            for angle, count in result.dominant_angles:
                table.add_row(f"{angle} to {angle+10}", str(count))
            console.print(table)
        else:
            console.print("[yellow]Could not find significant lines.[/yellow]")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)

@cli_app.command("aberration", help="Check for chromatic aberration / channel misalignment.")
def cli_analyze_aberration(
    file_path: str = typer.Argument(..., exists=True, help="Path to the image file.")
):
    """CLI command for analyze_chromatic_aberration."""
    try:
        analyzer = TechnicalImageAnalyzer(file_path)
        result = analyzer.analyze_chromatic_aberration()
        
        console.print(f"[bold]Chromatic Aberration Analysis:[/bold] {result.status}")
        if result.status == "completed":
            style = "bold red" if result.is_suspicious else "green"
            console.print(f"  Score: [{style}]{result.aberration_score:.4f}[/{style}] (Suspicious: {result.is_suspicious})")
            console.print(f"  Details: {result.details}")
            
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)

@cli_app.command("eyes", help="Analyze eye reflections for consistency.")
def cli_analyze_eyes(
    file_path: str = typer.Argument(..., exists=True, help="Path to the image file.")
):
    """CLI command for analyze_eye_reflections."""
    try:
        analyzer = TechnicalImageAnalyzer(file_path)
        result = analyzer.analyze_eye_reflections()
        
        console.print(f"[bold]Eye Reflection Analysis:[/bold] {result.status}")
        if result.status == "completed":
            style = "bold red" if result.is_suspicious else "green"
            console.print(f"  Histogram Correlation: [{style}]{result.histogram_correlation:.4f}[/{style}]")
            console.print(f"  Suspicious (mismatch): {result.is_suspicious}")
        else:
            console.print(f"[yellow]{result.error or result.status}[/yellow]")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)

@cli_app.command("lipsync", help="Analyze audio/video lip sync correlation.")
def cli_analyze_lipsync(
    file_path: str = typer.Argument(..., exists=True, help="Path to the video file.")
):
    """CLI command for analyze_lip_sync."""
    try:
        analyzer = TechnicalVideoAnalyzer(file_path)
        console.print("Analyzing lip sync (this may take a moment)...")
        result = analyzer.analyze_lip_sync()
        
        console.print(f"[bold]Lip Sync Analysis:[/bold] {result.status}")
        if result.status == "completed":
            style = "bold red" if result.is_suspicious else "green"
            console.print(f"  A/V Correlation Score: [{style}]{result.correlation_score:.4f}[/{style}]")
            console.print(f"  Suspicious (low/neg correlation): {result.is_suspicious}")
            console.print(f"  Frames Analyzed: {result.frames_analyzed}")
        else:
            console.print(f"[yellow]{result.error or result.status}[/yellow]")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)

@cli_app.command("all", help="Run all technical analyses on a media file.")
def cli_analyze_all(
    file_path: str = typer.Argument(..., exists=True, help="Path to the image/video file.")
):
    """Runs all analyses from this module."""
    p = Path(file_path)
    is_video = p.suffix.lower() in [".mp4", ".mov", ".avi", ".mkv"]
    
    console.print(f"[bold cyan]--- Technical Forensics Report for {p.name} ---[/bold cyan]")
    
    try:
        img_analyzer = TechnicalImageAnalyzer(file_path)
        cli_analyze_lighting.callback(file_path)
        cli_analyze_perspective.callback(file_path)
        cli_analyze_aberration.callback(file_path)
        cli_analyze_eyes.callback(file_path)
    except IOError:
        if not is_video:
            console.print("[bold red]Failed to load file as an image.[/bold red]")
            raise typer.Exit(code=1)
        console.print("[yellow]File is a video, skipping image-only analyses.[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Image analysis failed:[/bold red] {e}")
    
    if is_video:
        try:
            cli_analyze_lipsync.callback(file_path)
        except Exception as e:
            console.print(f"[bold red]Video analysis failed:[/bold red] {e}")
            
    console.print("[bold cyan]--- End of Report ---[/bold cyan]")


if __name__ == "__main__":
    cli_app()