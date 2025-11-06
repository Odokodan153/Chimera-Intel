"""
Chimera-Intel Advanced Ensemble Detector
=========================================

This module provides a high-level ensemble system for detecting synthetic media
by combining frame-level, temporal, and audio-based ML detectors.

It reuses existing detectors from media_forensics.py (XceptionNet) and
voice_analysis.py (Audio SVM) and adds new temporal analysis logic.
"""

import typer
import pathlib
import cv2
import numpy as np
import librosa
import os
from rich.console import Console
from rich.table import Table

# --- Reuse existing Chimera-Intel Modules ---
try:
    # 1. Reuse the XceptionNet frame-level detector
    from .media_forensics import deepfake_multimodal_scan, load_models as load_forensic_models
    from .schemas import EnsembleAnalysisResult, TemporalAnalysisResult, SyntheticVoiceAnalysisResult
except ImportError as e:
    print(f"Error: Could not import media_forensics. {e}")
    raise
try:
    # 2. Reuse the model-based audio classifier
    from .voice_analysis import VoiceAnalyzer
except ImportError as e:
    print(f"Error: Could not import voice_analysis. {e}")
    raise
from .schemas import BaseResult

console = Console()

ensemble_app = typer.Typer(
    name="ensemble",
    help="Run ensemble-based synthetic media detection (Frame + Temporal + Audio)."
)

# --- Detector Model Paths ---
# Assumes a pre-trained synthetic voice (ASV) model exists
SYNTHETIC_VOICE_MODEL_PATH = os.environ.get(
    "ASV_MODEL_PATH", "models/svm_asv_classifier"
)

# --- Core Logic ---

def load_models():
    """Load all required models for the ensemble."""
    console.print("Loading forensic (XceptionNet) models...")
    load_forensic_models()
    console.print("Checking for audio (ASV) models...")
    if not os.path.exists(SYNTHETIC_VOICE_MODEL_PATH):
        console.print(f"[yellow]Warning:[/yellow] Synthetic voice model not found at {SYNTHETIC_VOICE_MODEL_PATH}. Voice analysis will be skipped.")
    else:
        console.print(f"Synthetic voice model found at {SYNTHETIC_VOICE_MODEL_PATH}")

@ensemble_app.callback()
def main():
    """Load models when the CLI app is first invoked."""
    load_models()


def analyze_temporal_model(file_path: pathlib.Path) -> TemporalAnalysisResult:
    """
    Analyzes video for temporal artifacts using optical flow.
    This serves as a real-time detector for motion inconsistencies,
    simulating the goal of a 3D-CNN or I3D model.
    """
    result = TemporalAnalysisResult()
    try:
        cap = cv2.VideoCapture(str(file_path))
        ret, prvs_frame = cap.read()
        if not ret:
            result.error = "Could not read first frame of video."
            return result
        
        prvs_gray = cv2.cvtColor(prvs_frame, cv2.COLOR_BGR2GRAY)
        flow_magnitudes = []
        frame_count = 0

        while cap.isOpened() and frame_count < 150: # Limit to 150 frames
            ret, next_frame = cap.read()
            if not ret:
                break
            
            next_gray = cv2.cvtColor(next_frame, cv2.COLOR_BGR2GRAY)
            
            # Calculate dense optical flow
            flow = cv2.calcOpticalFlowFarneback(
                prvs_gray, next_gray, None, 0.5, 3, 15, 3, 5, 1.2, 0
            )
            
            # Calculate magnitude and angle of 2D vectors
            mag, ang = cv2.cartToMag(flow[..., 0], flow[..., 1])
            flow_magnitudes.append(np.mean(mag))
            
            prvs_gray = next_gray
            frame_count += 1
            
        cap.release()

        if not flow_magnitudes:
            result.error = "Could not calculate optical flow."
            return result

        # Detect high variance in motion (a temporal artifact)
        flow_std_dev = np.std(flow_magnitudes)
        score = 0.0
        details = f"Average optical flow std. dev: {flow_std_dev:.4f}."
        
        # Heuristic: High standard deviation in flow magnitude suggests jitter
        if flow_std_dev > 1.5:
            result.artifacts_found.append("Unnatural motion jitter detected (high flow variance).")
            # Normalize score
            score = min(1.0, (flow_std_dev - 1.5) / 2.0)

        result.temporal_inconsistency_score = score
        result.details = details
        return result

    except Exception as e:
        result.error = f"Failed during temporal analysis: {e}"
        if cap and cap.isOpened():
            cap.release()
        return result


def detect_synthetic_voice(file_path: pathlib.Path) -> SyntheticVoiceAnalysisResult:
    """
    Detects synthetic voice anomalies using the VoiceAnalyzer class.
    
    This function assumes a classifier model (e.g., SVM) trained on
    ASVspoof or similar datasets is located at SYNTHETIC_VOICE_MODEL_PATH.
    The model should be trained with labels like 'bonafide' and 'synthetic'.
    """
    result = SyntheticVoiceAnalysisResult()
    
    if not os.path.exists(SYNTHETIC_VOICE_MODEL_PATH):
        result.error = f"Synthetic voice model not found: {SYNTHETIC_VOICE_MODEL_PATH}"
        return result
        
    try:
        # Check if file has an audio stream
        try:
            librosa.load(str(file_path), sr=None, duration=1.0)
        except Exception:
             result.error = "File is not a valid audio file or has no audio stream."
             return result

        # Reuse existing VoiceAnalyzer for model-based classification
        analyzer = VoiceAnalyzer(model_path=SYNTHETIC_VOICE_MODEL_PATH)
        
        # We must re-map labels for this specific task
        # We assume the model was trained with 'bonafide' and 'synthetic'
        analyzer.emotion_labels = ["bonafide", "synthetic"]
        
        audio_result = analyzer.analyze_audio_tone(str(file_path))
        
        if not audio_result:
            result.error = "Audio analysis failed to produce a result."
            return result
        
        emotion = audio_result.get("detailed_emotion", "unknown")
        confidence = audio_result.get("confidence_score", 0.0)
        
        if emotion == "synthetic":
            result.is_synthetic = True
            result.confidence = confidence
        else: # bonafide or unknown
            result.is_synthetic = False
            result.confidence = confidence # Confidence in 'bonafide'
            
        result.details = f"Classifier '{SYNTHETIC_VOICE_MODEL_PATH}' prediction: {emotion} (Confidence: {confidence:.2%})"
        return result

    except Exception as e:
        result.error = f"Failed during synthetic voice detection: {e}"
        return result


@ensemble_app.command("run", help="Run the full detector ensemble (Frame+Temporal+Audio).")
def run_ensemble_analysis(
    file_path: pathlib.Path = typer.Argument(..., exists=True, help="Path to the media file (e.g., MP4).")
) -> EnsembleAnalysisResult:
    """
    Runs the full ensemble analysis:
    1. Frame-level (XceptionNet)
    2. Temporal (Optical Flow)
    3. Audio (ASV Classifier)
    
    Combines the results and provides an explainability report.
    """
    console.print(f"[bold magenta]Running Ensemble Analysis on:[/bold magenta] {file_path.name}")
    final_result = EnsembleAnalysisResult()
    
    # --- 1. Frame-level (XceptionNet) ---
    console.print("  - [1/3] Running frame-level detector (XceptionNet)...")
    frame_result = deepfake_multimodal_scan(file_path)
    final_result.frame_analysis = frame_result
    
    # --- 2. Temporal (Optical Flow) ---
    console.print("  - [2/3] Running temporal model (Optical Flow)...")
    temporal_result = analyze_temporal_model(file_path)
    final_result.temporal_analysis = temporal_result

    # --- 3. Audio (ASV Classifier) ---
    console.print("  - [3/3] Running audio detector (ASV Classifier)...")
    voice_result = detect_synthetic_voice(file_path)
    final_result.voice_analysis = voice_result

    # --- 4. Ensemble & Explainability ---
    
    # Get scores, handling errors
    frame_score = 0.0
    if not frame_result.error and frame_result.is_deepfake:
        frame_score = frame_result.confidence
        
    temporal_score = 0.0
    if not temporal_result.error:
        temporal_score = temporal_result.temporal_inconsistency_score
        
    voice_score = 0.0
    if not voice_result.error and voice_result.is_synthetic:
        voice_score = voice_result.confidence

    # Weighted ensemble
    # (These weights can be tuned)
    final_score = (frame_score * 0.5) + (temporal_score * 0.2) + (voice_score * 0.3)
    final_result.final_fake_probability = final_score

    # Build Explainability Report (Heatmap simulation)
    explain_report = {
        "summary": f"Final synthetic probability: {final_score:.2%}",
        "suspicious_visual_frames": "No significant artifacts found." 
                                     if frame_score < 0.5 
                                     else f"High fake probability ({frame_score:.2%}) detected in video frames. Details: {' '.join(frame_result.inconsistencies)}",
        "suspicious_temporal_segments": "No significant artifacts found."
                                        if temporal_score < 0.5
                                        else f"High temporal inconsistency ({temporal_score:.2%}) detected. Details: {' '.join(temporal_result.artifacts_found)}",
        "suspicious_audio_segments": "No significant artifacts found."
                                     if voice_score < 0.5
                                     else f"High synthetic voice probability ({voice_score:.2%}) detected. Details: {voice_result.details}"
    }
    final_result.explainability_report = explain_report
    
    # --- Print Rich Table Output ---
    console.print("\n[bold green]Ensemble Analysis Complete[/bold green]")
    table = Table(title="Ensemble Detector Results")
    table.add_column("Detector", style="cyan")
    table.add_column("Result (Prob. Fake)", style="magenta")
    table.add_column("Details", style="white")

    table.add_row(
        "Frame-level (XceptionNet)",
        f"{frame_score:.2%}",
        "[red]Error[/red]" if frame_result.error else " ".join(frame_result.inconsistencies)
    )
    table.add_row(
        "Temporal (Optical Flow)",
        f"{temporal_score:.2%}",
        "[red]Error[/red]" if temporal_result.error else temporal_result.details
    )
    table.add_row(
        "Audio (ASV Classifier)",
        f"{voice_score:.2%}",
        "[red]Error[/red]" if voice_result.error else voice_result.details
    )
    table.add_section()
    table.add_row(
        "[bold]Ensemble Result[/bold]",
        f"[bold]{final_score:.2%}[/bold]",
        "High" if final_score > 0.5 else "Low"
    )
    console.print(table)
    
    console.print("[bold]Explainability Report:[/bold]")
    for key, value in explain_report.items():
        console.print(f"  - [italic]{key}[/italic]: {value}")
        
    return final_result


@ensemble_app.command("temporal", help="Run only the temporal (optical flow) analysis.")
def cli_temporal(
    file_path: pathlib.Path = typer.Argument(..., exists=True, help="Path to the video file.")
):
    result = analyze_temporal_model(file_path)
    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
    else:
        console.print(f"Temporal Inconsistency Score: {result.temporal_inconsistency_score:.2%}")
        console.print(f"Details: {result.details}")
        console.print(f"Artifacts: {', '.join(result.artifacts_found)}")

@ensemble_app.command("synthetic-voice", help="Run only the synthetic voice (ASV) analysis.")
def cli_synthetic_voice(
    file_path: pathlib.Path = typer.Argument(..., exists=True, help="Path to the media file.")
):
    result = detect_synthetic_voice(file_path)
    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
    else:
        console.print(f"Is Synthetic: {result.is_synthetic}")
        console.print(f"Confidence: {result.confidence:.2%}")
        console.print(f"Details: {result.details}")