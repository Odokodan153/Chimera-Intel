import unittest
from unittest.mock import patch, MagicMock

from chimera_intel.core.media_analyzer import (
    reverse_image_search,
    transcribe_audio_file,
)
from chimera_intel.core.schemas import ReverseImageSearchResult, MediaAnalysisResult


class TestMediaAnalyzer(unittest.IsolatedAsyncioTestCase):
    """Test cases for the media_analyzer module."""

    # Note: Reverse image search is a placeholder, so we test its structure.

    async def test_reverse_image_search_structure(self):
        """Tests the basic structure of the reverse image search result."""
        result = await reverse_image_search("test.jpg")
        self.assertIsInstance(result, ReverseImageSearchResult)
        self.assertIsNone(result.error)
        # Check that the placeholder returns its expected simulated result

        self.assertEqual(result.matches_found, 1)

    @patch("chimera_intel.core.media_analyzer.sr.Recognizer")
    @patch("chimera_intel.core.media_analyzer.sr.AudioFile")
    def test_transcribe_audio_file_success(self, mock_audio_file, mock_recognizer):
        """Tests a successful audio transcription."""
        # Arrange

        mock_rec_instance = mock_recognizer.return_value
        mock_rec_instance.record.return_value = MagicMock()  # Mock audio data
        mock_rec_instance.recognize_whisper.return_value = "This is a test transcript."

        # Mock the AudioFile context manager

        mock_audio_file.return_value.__enter__.return_value = MagicMock()

        # Act

        result = transcribe_audio_file("test.wav")

        # Assert

        self.assertIsInstance(result, MediaAnalysisResult)
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.transcript)
        self.assertEqual(result.transcript.text, "This is a test transcript.")
        mock_rec_instance.recognize_whisper.assert_called_once()

    @patch("chimera_intel.core.media_analyzer.sr.Recognizer")
    def test_transcribe_audio_file_exception(self, mock_recognizer):
        """Tests error handling during transcription."""
        # Arrange

        mock_recognizer.side_effect = Exception("Whisper model not found")

        # Act

        result = transcribe_audio_file("test.wav")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("An error occurred during transcription", result.error)


if __name__ == "__main__":
    unittest.main()
