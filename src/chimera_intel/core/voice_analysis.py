import os
import numpy as np
from typing import Dict, Any, Optional
from pyAudioAnalysis import audioBasicIO
from pyAudioAnalysis import ShortTermFeatures
from pyAudioAnalysis import audioTrainTest as aT

# Note: This implementation requires a pre-trained audio classifier model.
# For this example, we'll assume a model named 'svm_emotion_classifier' exists in a 'models' directory.
# This model would be trained on a dataset like RAVDESS, TESS, or SAVEE.


class VoiceAnalyzer:
    """
    Analyzes vocal tone and sentiment from an audio input using real audio processing techniques.
    """

    def __init__(self, model_path: str = "models/svm_emotion_classifier"):
        """
        Initializes the analyzer and loads the pre-trained emotion classification model.
        """
        self.model_path = model_path
        self.emotion_labels = [
            "neutral",
            "calm",
            "happy",
            "sad",
            "angry",
            "fearful",
            "disgust",
            "surprised",
        ]

        if not os.path.exists(self.model_path):
            print(
                f"Warning: Classifier model not found at '{self.model_path}'. Voice analysis will be disabled."
            )
            self.model_loaded = False
        else:
            self.model_loaded = True

    def analyze_audio_tone(self, audio_file_path: str) -> Optional[Dict[str, Any]]:
        """
        Takes a path to an audio file and returns a real analysis of its vocal characteristics.

        Args:
            audio_file_path (str): The path to the WAV audio file to be analyzed.

        Returns:
            A dictionary containing the vocal analysis, or None if analysis fails.
        """
        if not self.model_loaded or not os.path.exists(audio_file_path):
            return None
        try:
            # Use pyAudioAnalysis for classification
            # The file_classification function returns: (winner_class_index, probability_distribution, class_labels)

            winner_idx, probabilities, labels = aT.file_classification(
                audio_file_path, self.model_path, "svm"
            )

            winner_label = labels[int(winner_idx)]
            confidence = probabilities[int(winner_idx)]

            # Extract basic acoustic features for pace and pitch

            sampling_rate, signal_data = audioBasicIO.read_audio_file(audio_file_path)
            features, feature_names = ShortTermFeatures.feature_extraction(
                signal_data, sampling_rate, 0.050 * sampling_rate, 0.025 * sampling_rate
            )

            # Simulate pace and pitch from feature stats (this is a simplification)

            energy = np.mean(features[feature_names.index("energy")])
            pitch = np.mean(features[feature_names.index("pitch")])

            vocal_pace = "normal"
            if energy > np.mean(features[0, :]):  # A simple heuristic
                vocal_pace = "fast"
            elif energy < np.mean(features[0, :]) * 0.5:
                vocal_pace = "slow"
            pitch_variation = "medium"
            if pitch > 180:  # Another simple heuristic
                pitch_variation = "high"
            elif pitch < 100:
                pitch_variation = "low"
            # Map the detailed emotion to our simplified sentiment categories

            vocal_sentiment = self._map_emotion_to_sentiment(winner_label)

            return {
                "vocal_sentiment": vocal_sentiment,
                "confidence_score": round(float(confidence), 2),
                "pace": vocal_pace,
                "pitch_variation": pitch_variation,
                "detailed_emotion": winner_label,
            }
        except Exception as e:
            print(f"Error during voice analysis: {e}")
            return None

    def _map_emotion_to_sentiment(self, emotion: str) -> str:
        """Maps a detailed emotion label to a simpler negotiation sentiment."""
        if emotion in ["angry", "disgust", "fearful"]:
            return "anxious"
        if emotion in ["sad"]:
            return "hesitant"
        if emotion in ["happy", "surprised"]:
            return "confident"
        return "neutral"  # calm, neutral
