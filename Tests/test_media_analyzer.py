import unittest
from unittest.mock import patch, MagicMock, mock_open

from chimera_intel.core.media_analyzer import (
    reverse_image_search,
    transcribe_audio_file,
)
from chimera_intel.core.schemas import ReverseImageSearchResult, MediaAnalysisResult


class TestMediaAnalyzer(unittest.IsolatedAsyncioTestCase):
    """Test cases for the media_analyzer module."""

    @patch("chimera_intel.core.media_analyzer.sync_client")
    @patch("builtins.open", new_callable=mock_open, read_data=b"image data")
    async def test_reverse_image_search_success(self, mock_file, mock_sync_client):
        """Tests a successful reverse image search."""
        # Arrange

        mock_post_response = MagicMock()
        mock_post_response.headers = {
            "Location": "https://www.google.com/search?q=test"
        }

        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.text = """
        <html><body>
            <div class="g">
                <a href="http://example.com/page1"><h3>Page Title 1</h3></a>
            </div>
            <div class="g">
                <a href="http://example.com/page2"><h3>Page Title 2</h3></a>
            </div>
        </body></html>
        """

        mock_sync_client.post.return_value = mock_post_response
        mock_sync_client.get.return_value = mock_get_response

        # Act

        result = await reverse_image_search("test.jpg")

        # Assert

        self.assertIsInstance(result, ReverseImageSearchResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.matches_found, 2)
        self.assertEqual(result.matches[0].page_title, "Page Title 1")
        self.assertEqual(result.matches[1].page_url, "http://example.com/page2")

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
    @patch("chimera_intel.core.media_analyzer.sr.AudioFile")
    def test_transcribe_audio_file_exception(self, mock_audio_file, mock_recognizer):
        """Tests error handling during transcription."""
        # Arrange

        mock_rec_instance = mock_recognizer.return_value
        mock_rec_instance.recognize_whisper.side_effect = Exception(
            "Whisper model not found"
        )
        mock_audio_file.return_value.__enter__.return_value = MagicMock()

        # Act

        result = transcribe_audio_file("test.wav")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("An error occurred during transcription", result.error)


if __name__ == "__main__":
    unittest.main()
