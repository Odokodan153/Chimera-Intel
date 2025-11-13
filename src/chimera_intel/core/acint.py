# src/chimera_intel/core/acint.py

import librosa
import numpy as np
import os
import json
import typer
from pathlib import Path
from scipy.spatial.distance import euclidean
from typing import Dict, Optional, Tuple

class AcousticIntelligence:
    """
    Handles Acoustic Intelligence (ACINT) tasks, focusing on non-human
    acoustic signatures from machinery, vehicles, and environmental events.
    """

    def __init__(self):
        """
        Initializes the ACINT module with an empty signature library.
        """
        self.signature_library: Dict[str, np.ndarray] = {}

    def _extract_features(self, file_path: str) -> Optional[np.ndarray]:
        """
        Extracts MFCC features from an audio file.

        Args:
            file_path: Path to the audio file.

        Returns:
            A 1D NumPy array representing the mean MFCC features, or None on error.
        """
        if not os.path.exists(file_path):
            print(f"Error: File not found at {file_path}")
            return None
        
        try:
            # Load audio file, sr=None preserves original sample rate
            y, sr = librosa.load(file_path, sr=None)
            
            # Extract 20 MFCCs
            mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=20)
            
            # Calculate the mean of MFCCs across time to get a single,
            # fixed-size feature vector (signature)
            mean_mfccs = np.mean(mfccs.T, axis=0)
            
            return mean_mfccs
            
        except Exception as e:
            print(f"Error processing audio file {file_path}: {e}")
            return None

    def add_to_library(self, file_path: str, name: str) -> bool:
        """
        Adds an audio file's signature to the library.

        Args:
            file_path: Path to the audio file.
            name: The unique name for this signature (e.g., "T-72_Tank_Engine").

        Returns:
            True if successful, False otherwise.
        """
        features = self._extract_features(file_path)
        
        if features is not None:
            self.signature_library[name] = features
            print(f"Added '{name}' to signature library.")
            return True
        
        return False

    def identify_sound(self, file_path: str, threshold: float = 0.5) -> Tuple[str, Optional[float]]:
        """
        Identifies an audio signature by comparing it to the library.

        Args:
            file_path: Path to the audio file to identify.
            threshold: The maximum distance for a positive match.

        Returns:
            A tuple containing the name of the closest match (or "Unknown Signature")
            and the distance of the match.
        """
        test_features = self._extract_features(file_path)
        
        if test_features is None:
            return "Error processing file", None

        if not self.signature_library:
            return "No signatures in library", None

        distances = {}
        for name, features in self.signature_library.items():
            dist = euclidean(test_features, features)
            distances[name] = dist
            
        closest_name = min(distances, key=distances.get)
        closest_distance = distances[closest_name]

        if closest_distance < threshold:
            return closest_name, closest_distance
        
        return "Unknown Signature", closest_distance

    def detect_anomaly(self, file_path: str, baseline_name: str, threshold: float = 2.0) -> Dict:
        """
        Detects if a sound is an anomaly compared to a baseline soundscape.

        Args:
            file_path: Path to the audio file to check.
            baseline_name: The name of the baseline signature in the library
                           (e.g., "normal_city_ambience").
            threshold: The distance beyond which the sound is considered an anomaly.

        Returns:
            A dictionary with anomaly status, distance, and threshold.
        """
        if baseline_name not in self.signature_library:
            return {"error": f"Baseline signature '{baseline_name}' not in library."}
            
        baseline_features = self.signature_library[baseline_name]
        test_features = self._extract_features(file_path)
        
        if test_features is None:
            return {"error": "Could not process test audio file."}

        dist = euclidean(test_features, baseline_features)
        is_anomaly = dist > threshold
        
        return {
            "is_anomaly": is_anomaly,
            "distance": float(dist),
            "threshold": threshold,
            "baseline": baseline_name
        }

    def save_library(self, file_path: str):
        """
        Saves the signature library to a JSON file.

        Args:
            file_path: The file path to save to.
        """
        # Convert numpy arrays to lists for JSON serialization
        data = {name: features.tolist() for name, features in self.signature_library.items()}
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"Signature library saved to {file_path}")
        except Exception as e:
            print(f"Error saving library: {e}")

    def load_library(self, file_path: str):
        """
        Loads the signature library from a JSON file.

        Args:
            file_path: The file path to load from.
        """
        if not os.path.exists(file_path):
            self.signature_library = {}
            return

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Convert lists back to numpy arrays
            self.signature_library = {name: np.array(features) for name, features in data.items()}
            print(f"Signature library loaded from {file_path}")
        except Exception as e:
            print(f"Error loading library: {e}")
            self.signature_library = {}


# --- CLI Section ---

acint_app = typer.Typer(help="Acoustic Intelligence (ACINT) Operations")

# Use a persistent location for the library
LIBRARY_PATH = "acint_library.json"
acint_instance = AcousticIntelligence()

@acint_app.callback(invoke_without_command=True)
def load_library():
    """
    Load the ACINT signature library before executing any command.
    """
    acint_instance.load_library(LIBRARY_PATH)

@acint_app.command("add")
def add_signature(
    file_path: Path = typer.Option(
        ..., 
        "--file", 
        "-f", 
        help="Path to the audio file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True
    ),
    name: str = typer.Option(
        ..., 
        "--name", 
        "-n", 
        help="Name of the signature (e.g., 'T-72_Engine')."
    )
):
    """
    Add a new acoustic signature to the library.
    """
    if acint_instance.add_to_library(str(file_path), name):
        acint_instance.save_library(LIBRARY_PATH)
        typer.secho(f"Successfully added '{name}' to library.", fg=typer.colors.GREEN)
    else:
        typer.secho(f"Failed to add '{name}'.", fg=typer.colors.RED)

@acint_app.command("identify")
def identify_signature(
    file_path: Path = typer.Option(
        ..., 
        "--file", 
        "-f", 
        help="Path to the audio file to identify.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True
    ),
    threshold: float = typer.Option(
        0.5, 
        "--threshold", 
        "-t", 
        help="Identification sensitivity threshold (lower is stricter)."
    )
):
    """
    Identify an audio file's signature against the library.
    """
    name, distance = acint_instance.identify_sound(str(file_path), threshold)
    
    if name == "Error processing file":
        typer.secho(f"Error processing file: {file_path}", fg=typer.colors.RED)
    elif name == "No signatures in library":
        typer.secho("The signature library is empty. Use 'add' to add signatures.", fg=typer.colors.YELLOW)
    elif name == "Unknown Signature":
        typer.secho(f"Signature: Unknown (Closest match: {distance:.4f})", fg=typer.colors.YELLOW)
    else:
        typer.secho(f"Signature: {name} (Distance: {distance:.4f})", fg=typer.colors.GREEN)

@acint_app.command("monitor")
def monitor_sound(
    file_path: Path = typer.Option(
        ..., 
        "--file", 
        "-f", 
        help="Path to the audio file to monitor for anomalies.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True
    ),
    baseline: str = typer.Option(
        "baseline_ambience", 
        "--baseline", 
        "-b", 
        help="Name of the baseline signature to compare against."
    ),
    threshold: float = typer.Option(
        2.0, 
        "--threshold", 
        "-t", 
        help="Anomaly detection threshold (higher allows more deviation)."
    )
):
    """
    Monitor an audio file for anomalies against a baseline signature.
    """
    result = acint_instance.detect_anomaly(str(file_path), baseline, threshold)
    
    if "error" in result:
        typer.secho(f"Error: {result['error']}", fg=typer.colors.RED)
    elif result["is_anomaly"]:
        typer.secho(
            f"Anomaly DETECTED! Distance: {result['distance']:.2f} (Threshold: {result['threshold']})",
            fg=typer.colors.RED,
            bold=True
        )
    else:
        typer.secho(
            f"No anomaly detected. Distance: {result['distance']:.2f} (Threshold: {result['threshold']})",
            fg=typer.colors.GREEN
        )