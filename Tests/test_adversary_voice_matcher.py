"""
Tests for the Adversary Voice Matcher module.

This test file creates a temporary, real audio library on disk
using numpy and scipy to test the feature extraction and DTW comparison.
"""

import pytest
import os
import shutil
import numpy as np
from scipy.io import wavfile
from typer.testing import CliRunner

# Requires dtw-python
pytest.importorskip("dtw")

from chimera_intel.core.adversary_voice_matcher import (
    match_adversary_voice,
    ADVERSARY_VOICE_LIBRARY_PATH,
    voice_match_app
)

runner = CliRunner()

# --- Test Fixture: Create a Real Audio Library ---

@pytest.fixture(scope="module")
def test_audio_lib():
    """
    Creates a temporary directory structure with real .wav files
    for testing the voice matcher.
    """
    SAMPLING_RATE = 22050
    DURATION = 2
    
    def create_sine_wave(freq, duration, sr):
        t = np.linspace(0., duration, int(sr * duration), endpoint=False)
        amplitude = np.iinfo(np.int16).max
        signal = amplitude * np.sin(2. * np.pi * freq * t)
        return signal.astype(np.int16)

    # Define file paths
    lib_path = ADVERSARY_VOICE_LIBRARY_PATH
    target_path = "temp_target_audio"
    
    # Create adversary "A" (440Hz)
    adv_a_signal = create_sine_wave(440, DURATION, SAMPLING_RATE)
    adv_a_path = os.path.join(lib_path, "adversary_A_440Hz.wav")
    
    # Create adversary "B" (880Hz)
    adv_b_signal = create_sine_wave(880, DURATION, SAMPLING_RATE)
    adv_b_path = os.path.join(lib_path, "adversary_B_880Hz.wav")
    
    # Create target "Match A" (identical to A)
    target_match_signal = create_sine_wave(440, DURATION, SAMPLING_RATE)
    target_match_path = os.path.join(target_path, "target_match_A.wav")
    
    # Create target "No Match" (660Hz)
    target_no_match_signal = create_sine_wave(660, DURATION, SAMPLING_RATE)
    target_no_match_path = os.path.join(target_path, "target_no_match.wav")

    # Setup: Create dirs and write files
    os.makedirs(lib_path, exist_ok=True)
    os.makedirs(target_path, exist_ok=True)
    
    wavfile.write(adv_a_path, SAMPLING_RATE, adv_a_signal)
    wavfile.write(adv_b_path, SAMPLING_RATE, adv_b_signal)
    wavfile.write(target_match_path, SAMPLING_RATE, target_match_signal)
    wavfile.write(target_no_match_path, SAMPLING_RATE, target_no_match_signal)

    # Yield the paths to the tests
    yield {
        "match": target_match_path,
        "no_match": target_no_match_path
    }
    
    # Teardown: Clean up the temporary directories
    shutil.rmtree(lib_path)
    shutil.rmtree(target_path)

# --- Tests ---

def test_adversary_voice_positive_match(test_audio_lib):
    """
    Tests that a file identical to a library file is matched.
    The DTW distance should be ~0, so similarity should be ~1.0.
    """
    target_file = test_audio_lib["match"]
    threshold = 0.9 # High threshold, should still pass
    
    result = match_adversary_voice(target_file, threshold=threshold)
    
    assert result.error is None
    assert len(result.matches_found) == 1
    
    match = result.matches_found[0]
    assert match.known_adversary_file == "adversary_A_440Hz.wav"
    assert match.decision == "Match"
    assert match.similarity_score > 0.99 # Should be almost perfect

def test_adversary_voice_no_match(test_audio_lib):
    """
    Tests that a file different from all library files is not matched.
    """
    target_file = test_audio_lib["no_match"]
    threshold = 0.8
    
    result = match_adversary_voice(target_file, threshold=threshold)
    
    assert result.error is None
    assert len(result.matches_found) == 0
    assert "No matches found" in result.status

def test_adversary_voice_cli_match(test_audio_lib):
    """Tests the CLI command for a positive match."""
    target_file = test_audio_lib["match"]
    
    result = runner.invoke(voice_match_app, ["adversary-voice-match", target_file, "--threshold", "0.9"])
    
    assert result.exit_code == 0
    assert "ADVERSARY MATCH FOUND" in result.stdout
    assert "adversary_A_440Hz.wav" in result.stdout