"""
Biometric Intelligence (BIOMINT) Module for Chimera Intel.

Provides tools for face and voice biometric analysis.

Requires:
- opencv-python-headless
- face_recognition
- dtw-python
- pyAudioAnalysis
"""

import typer
import os
import numpy as np
import logging
from typing import Optional, List
from pydantic import BaseModel, Field
from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.adversary_voice_matcher import _extract_features, _compare_features
from chimera_intel.core.schemas import FaceAnalysisResult,VoiceComparisonResult

# Conditional import for face_recognition and cv2
try:
    import face_recognition
    import cv2
    FACE_LIBS_AVAILABLE = True
except ImportError:
    FACE_LIBS_AVAILABLE = False
    # Create dummy classes for type hinting if libs are missing
    class cv2:
        VideoCapture = type("VideoCapture", (object,), {})
        
    class face_recognition:
        face_locations = type("face_locations", (object,), {})
        face_encodings = type("face_encodings", (object,), {})
        compare_faces = type("compare_faces", (object,), {})

logger = logging.getLogger(__name__)


def analyze_face(file_path: str) -> FaceAnalysisResult:
    """
    Analyzes an image or video file to detect and locate human faces.
    """
    if not FACE_LIBS_AVAILABLE:
        return FaceAnalysisResult(
            file_path=file_path,
            error="Missing 'face_recognition' or 'opencv-python'. Please install them."
        )
    
    if not os.path.exists(file_path):
        return FaceAnalysisResult(file_path=file_path, error="File not found.")

    locations = []
    try:
        # Try to load as image first
        image = face_recognition.load_image_file(file_path)
        face_locations = face_recognition.face_locations(image)
        for loc in face_locations:
            locations.append({"top": loc[0], "right": loc[1], "bottom": loc[2], "left": loc[3]})
        
        return FaceAnalysisResult(
            file_path=file_path,
            faces_found=len(face_locations),
            face_locations=locations
        )
    except Exception as e_img:
        logger.warning(f"Could not process {file_path} as image ({e_img}), trying video.")
        # If image processing fails, try video (simplified)
        try:
            video = cv2.VideoCapture(file_path)
            if not video.isOpened():
                return FaceAnalysisResult(file_path=file_path, error="Could not open file as image or video.")
            
            # Read one frame
            ret, frame = video.read()
            if not ret:
                video.release()
                return FaceAnalysisResult(file_path=file_path, error="Could not read video frame.")
            
            # Detect faces in the single frame
            rgb_frame = frame[:, :, ::-1] # BGR to RGB
            face_locations = face_recognition.face_locations(rgb_frame)
            for loc in face_locations:
                locations.append({"top": loc[0], "right": loc[1], "bottom": loc[2], "left": loc[3]})
            
            video.release()
            return FaceAnalysisResult(
                file_path=file_path,
                faces_found=len(face_locations),
                face_locations=locations,
                status="Analyzed first frame of video"
            )
        except Exception as e_vid:
            return FaceAnalysisResult(file_path=file_path, error=f"File processing failed: {e_vid}")


def compare_voices(file_a: str, file_b: str, threshold: float = 0.8) -> VoiceComparisonResult:
    """
    Compares two audio files to determine if the voices are a match.
    Reuses logic from AdversaryVoiceMatcher.
    """
    result = VoiceComparisonResult(file_a=file_a, file_b=file_b, threshold=threshold)

    try:
        features_a = _extract_features(file_a)
        if features_a is None:
            result.error = f"Could not extract features from {file_a}"
            return result

        features_b = _extract_features(file_b)
        if features_b is None:
            result.error = f"Could not extract features from {file_b}"
            return result
        
        similarity = _compare_features(features_a, features_b)
        result.similarity_score = round(similarity, 4)
        
        if similarity >= threshold:
            result.decision = "Match"
        
        result.status = "Completed"
        return result
        
    except ImportError as e:
        result.error = "Missing 'dtw-python'. Please run: pip install dtw-python"
        return result
    except Exception as e:
        result.error = f"An error occurred during voice comparison: {e}"
        return result

# --- CLI Application ---

biomint_app = typer.Typer(
    name="biomint",
    help="Biometric Intelligence (BIOMINT) for face and voice analysis.",
)

@biomint_app.command(
    "analyze-face",
    help="Detect and locate faces in an image or video file.",
)
def run_analyze_face(
    file_path: str = typer.Argument(..., help="Path to the image or video file."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    CLI command to analyze a file for faces.
    """
    if not FACE_LIBS_AVAILABLE:
        console.print("[bold red]Error: 'face_recognition' and 'opencv-python' libraries are required.[/bold red]")
        console.print("Please run: pip install face_recognition opencv-python-headless")
        raise typer.Exit(code=1)
        
    console.print(f"[cyan]Analyzing file for faces:[/cyan] {file_path}")
    result = analyze_face(file_path)
    save_or_print_results(result.model_dump(), output_file)

@biomint_app.command(
    "compare-voices",
    help="Compare two audio files to see if the voices match.",
)
def run_compare_voices(
    file_a: str = typer.Argument(..., help="Path to the first audio file."),
    file_b: str = typer.Argument(..., help="Path to the second audio file."),
    threshold: float = typer.Option(0.8, "--threshold", "-t", help="Similarity threshold for a match (0.0 to 1.0)."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    CLI command to compare two voices.
    """
    console.print(f"[cyan]Comparing voices:[/cyan]")
    console.print(f"  - File A: {file_a}")
    console.print(f"  - File B: {file_b}")
    console.print(f"  - Threshold: {threshold}")
    
    result = compare_voices(file_a, file_b, threshold)
    save_or_print_results(result.model_dump(), output_file)
    
    if result.decision == "Match":
        console.print(f"\n[bold green]VOICE MATCH FOUND![/bold green] (Similarity: {result.similarity_score})")
    else:
        console.print(f"\n[yellow]No match found.[/yellow] (Similarity: {result.similarity_score})")