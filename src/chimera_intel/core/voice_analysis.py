"""
Analyzes vocal tone and sentiment from audio files using pre-trained emotion classification models 
or fallback heuristics. Provides metrics such as pace, pitch variation, and a mapped sentiment 
to support voice-based insights in negotiations or user interactions.
"""

import os
import numpy as np
import logging
from typing import Dict, Any, Optional, List
from pyAudioAnalysis import audioBasicIO, ShortTermFeatures, audioTrainTest as aT

# Configure structured logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class VoiceAnalyzer:
    """
    Analyzes vocal tone and sentiment from an audio input using audio processing techniques.
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
            logger.warning(
                f"Classifier model not found at '{self.model_path}'. "
                "Voice analysis will fall back to a basic heuristic model."
            )
            self.model_loaded = False
        else:
            self.model_loaded = True

    def analyze_audio_tone(self, audio_file_path: str) -> Optional[Dict[str, Any]]:
        """
        Analyzes an audio file for vocal characteristics. If a model is loaded,
        it performs emotion classification. Otherwise, it falls back to heuristics.
        """
        if not os.path.exists(audio_file_path):
            logger.error(f"Audio file not found at: {audio_file_path}")
            return None
        try:
            sampling_rate, signal_data = audioBasicIO.read_audio_file(audio_file_path)
            features, feature_names = ShortTermFeatures.feature_extraction(
                signal_data,
                sampling_rate,
                0.050 * sampling_rate,
                0.025 * sampling_rate,
            )

            if self.model_loaded:
                return self._analyze_with_model(
                    audio_file_path, features, feature_names
                )
            else:
                return self._analyze_with_heuristics(features, feature_names)
        except Exception as e:
            logger.error(f"Error during voice analysis for {audio_file_path}: {e}")
            return None

    def _analyze_with_model(
        self, audio_file_path: str, features: np.ndarray, feature_names: List[str]
    ) -> Dict[str, Any]:
        """Performs analysis using the pre-trained classifier."""
        winner_idx, probabilities, labels = aT.file_classification(
            audio_file_path, self.model_path, "svm"
        )
        winner_label = labels[int(winner_idx)]
        confidence = probabilities[int(winner_idx)]

        pace, pitch_variation = self._get_pace_and_pitch(features, feature_names)
        vocal_sentiment = self._map_emotion_to_sentiment(winner_label)

        return {
            "vocal_sentiment": vocal_sentiment,
            "confidence_score": round(float(confidence), 2),
            "pace": pace,
            "pitch_variation": pitch_variation,
            "detailed_emotion": winner_label,
            "analysis_type": "model-based",
        }

    def _analyze_with_heuristics(
        self, features: np.ndarray, feature_names: List[str]
    ) -> Dict[str, Any]:
        """Performs a basic analysis when no model is available."""
        pace, pitch_variation = self._get_pace_and_pitch(features, feature_names)
        vocal_sentiment = "neutral"  # Default sentiment without a model

        # A simple heuristic for sentiment based on energy and pitch

        energy_mean = np.mean(features[feature_names.index("energy")])
        pitch_mean = np.mean(features[feature_names.index("pitch")])

        if energy_mean > 0.1 and pitch_mean > 150:
            vocal_sentiment = "confident"
        elif energy_mean < 0.05:
            vocal_sentiment = "hesitant"
        return {
            "vocal_sentiment": vocal_sentiment,
            "confidence_score": 0.5,  # Indicates a heuristic guess
            "pace": pace,
            "pitch_variation": pitch_variation,
            "detailed_emotion": "unknown",
            "analysis_type": "heuristic-based",
        }

    def _get_pace_and_pitch(
        self, features: np.ndarray, feature_names: List[str]
    ) -> tuple[str, str]:
        """Calculates pace and pitch from audio features."""
        energy = features[feature_names.index("energy")]
        pitch = features[feature_names.index("pitch")]

        # Calibrated thresholds based on typical speech patterns

        vocal_pace = "normal"
        if np.mean(energy) > 0.08:
            vocal_pace = "fast"
        elif np.mean(energy) < 0.03:
            vocal_pace = "slow"
        pitch_variation = "medium"
        if np.std(pitch) > 60:
            pitch_variation = "high"
        elif np.std(pitch) < 20:
            pitch_variation = "low"
        return vocal_pace, pitch_variation

    def _map_emotion_to_sentiment(self, emotion: str) -> str:
        """Maps a detailed emotion label to a simpler negotiation sentiment."""
        mapping = {
            "angry": "anxious",
            "disgust": "anxious",
            "fearful": "anxious",
            "sad": "hesitant",
            "happy": "confident",
            "surprised": "confident",
        }
        return mapping.get(emotion, "neutral")
