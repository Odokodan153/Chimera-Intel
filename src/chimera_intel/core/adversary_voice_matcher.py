"""
Adversary Voice Matching Module for Chimera Intel.

Builds a library of known adversary synthetic voices and flags new
audio files that match a known fraudulent profile.

This module reuses the audio processing foundation from voice_analysis.py
and adds Dynamic Time Warping (DTW) for more accurate comparison.

Requires: dtw-python
"""

import typer
import os
import numpy as np
import logging
from chimera_intel.core.schemas import VoiceMatch,AdversaryVoiceMatchResult
from typing import Optional
from pyAudioAnalysis import audioBasicIO, ShortTermFeatures

# --- Import for Enhanced Heuristic ---
try:
    from dtw import dtw
except ImportError:
    print("ERROR: Missing 'dtw-python'. Please run: pip install dtw-python")
    dtw = None

from chimera_intel.core.utils import console, save_or_print_results

logger = logging.getLogger(__name__)


ADVERSARY_VOICE_LIBRARY_PATH = "models/adversary_voices"


def _extract_features(file_path: str) -> Optional[np.ndarray]:
    """
    Extracts short-term features from an audio file.
    Reuses the core logic from VoiceAnalyzer.
    """
    if not os.path.exists(file_path):
        logger.error(f"Audio file not found at: {file_path}")
        return None
    try:
        sampling_rate, signal_data = audioBasicIO.read_audio_file(file_path)
        # Ensure mono for consistent feature extraction
        if signal_data.ndim > 1:
            signal_data = signal_data.mean(axis=1)
            
        features, feature_names = ShortTermFeatures.feature_extraction(
            signal_data,
            sampling_rate,
            0.050 * sampling_rate,
            0.025 * sampling_rate,
        )
        return features
    except Exception as e:
        logger.error(f"Error extracting features from {file_path}: {e}")
        return None

def _compare_features(features1: np.ndarray, features2: np.ndarray) -> float:
    """
    Compares two feature matrices using Dynamic Time Warping (DTW)
    for a more robust, time-series-aware similarity score.
    """
    if dtw is None:
        raise ImportError("The 'dtw-python' library is required for voice matching.")
        
    try:
        # Transpose matrices so shape is (n_frames, n_features)
        # DTW will compare the sequence of feature vectors over time.
        f1 = features1.T
        f2 = features2.T
        
        # Normalize features to prevent scaling issues
        f1 = (f1 - f1.mean(axis=0)) / (f1.std(axis=0) + 1e-9)
        f2 = (f2 - f2.mean(axis=0)) / (f2.std(axis=0) + 1e-9)

        # Calculate normalized DTW distance
        # This finds the optimal alignment between the two voice prints.
        alignment = dtw(f1, f2, keep_internals=True)
        
        # Normalized distance (0 = identical, >0 = different)
        distance = alignment.normalizedDistance
        
        # Convert distance to similarity (1.0 = identical, 0.0 = very different)
        # We cap at 1.0 (distance can't be negative)
        similarity = max(0.0, 1.0 - distance)
        
        return float(similarity)
    except Exception as e:
        logger.error(f"Error during DTW comparison: {e}")
        return 0.0

def match_adversary_voice(new_audio_file: str, threshold: float = 0.8) -> AdversaryVoiceMatchResult:
    """
    Compares a new audio file against the library of known adversary voices.
    NOTE: DTW is more sensitive, so the default threshold is lowered to 0.8.
    """
    logger.info(f"Matching adversary voice for file: {new_audio_file}")
    
    if not os.path.exists(ADVERSARY_VOICE_LIBRARY_PATH):
        logger.error(f"Adversary voice library not found at: {ADVERSARY_VOICE_LIBRARY_PATH}")
        return AdversaryVoiceMatchResult(
            new_audio_file=new_audio_file,
            match_threshold=threshold,
            status="Error",
            error=f"Adversary voice library not found: {ADVERSARY_VOICE_LIBRARY_PATH}"
        )

    new_features = _extract_features(new_audio_file)
    if new_features is None:
        return AdversaryVoiceMatchResult(
            new_audio_file=new_audio_file,
            match_threshold=threshold,
            status="Error",
            error="Could not extract features from new audio file."
        )

    result = AdversaryVoiceMatchResult(new_audio_file=new_audio_file, match_threshold=threshold)

    for adversary_file in os.listdir(ADVERSARY_VOICE_LIBRARY_PATH):
        if adversary_file.endswith((".wav", ".mp3")):
            adversary_path = os.path.join(ADVERSARY_VOICE_LIBRARY_PATH, adversary_file)
            logger.info(f"Comparing against: {adversary_file}")
            
            known_features = _extract_features(adversary_path)
            if known_features is None:
                continue

            similarity = _compare_features(new_features, known_features)
            
            match = VoiceMatch(known_adversary_file=adversary_file, similarity_score=round(similarity, 4))
            if similarity >= threshold:
                match.decision = "Match"
                result.matches_found.append(match)

    if not result.matches_found:
        result.status = "Completed - No matches found"
    
    return result

# --- CLI Application ---

voice_match_app = typer.Typer(
    name="voice-match",
    help="Adversary synthetic voice matching.",
)

@voice_match_app.command(
    "adversary-voice-match",
    help="Check audio against a library of known fraudulent voices.",
)
def run_adversary_voice_match(
    new_audio_file: str = typer.Argument(..., help="Path to the new audio file to check."),
    threshold: float = typer.Option(0.8, "--threshold", "-t", help="Similarity threshold for a match (0.0 to 1.0)."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes an audio file and compares its voice print against a known
    library of adversary voices (e.g., for vishing/fraud detection).
    
    Uses Dynamic Time Warping (DTW) for robust comparison.
    """
    if dtw is None:
        console.print("[bold red]Error: 'dtw-python' library not found. Please run 'pip install dtw-python'.[/bold red]")
        raise typer.Exit(code=1)
        
    console.print(f"[bold cyan]Matching voice from:[/bold cyan] '{new_audio_file}'")
    console.print(f"  - Using DTW threshold: {threshold}")
    console.print(f"  - Library: {ADVERSARY_VOICE_LIBRARY_PATH}")
    
    result = match_adversary_voice(new_audio_file, threshold)
    
    save_or_print_results(result.model_dump(), output_file)
    
    if any(m.decision == "Match" for m in result.matches_found):
        console.print(f"\n[bold red]ADVERSARY MATCH FOUND![/bold red]")
        for match in result.matches_found:
            if match.decision == "Match":
                console.print(f"  - [yellow]{match.known_adversary_file}[/yellow] (Similarity: {match.similarity_score})")