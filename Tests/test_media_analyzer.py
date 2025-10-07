import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock, mock_open
from typer.testing import CliRunner
import json

from chimera_intel.core.media_analyzer import (
    reverse_image_search,
    transcribe_audio_file,
    media_app,
)
from chimera_intel.core.schemas import (
    ReverseImageSearchResult,
    MediaAnalysisResult,
    MediaTranscript,
)

runner = CliRunner()


class TestMediaAnalyzer(unittest.IsolatedAsyncioTestCase):
    """Test cases for the Image, Video, and Audio Intelligence (IMINT/VIDINT) module."""

    # --- Reverse Image Search Tests ---

    @patch("chimera_intel.core.media_analyzer.sync_client")
    async def test_reverse_image_search_success(self, mock_sync_client):
        """Tests a successful reverse image search."""
        # Arrange

        mock_post_response = MagicMock()
        mock_post_response.headers = {"Location": "http://google.com/searchresults"}
        mock_get_response = MagicMock()
        mock_get_response.raise_for_status.return_value = None
        mock_get_response.text = """
        <html><body><div class="g">
            <a href="http://example.com/page"><h3>Page Title</h3></a>
        </div></body></html>
        """
        mock_sync_client.post.return_value = mock_post_response
        mock_sync_client.get.return_value = mock_get_response

        with patch("builtins.open", mock_open(read_data=b"imagedata")):
            # Act

            result = await reverse_image_search("test.jpg")
        # Assert

        self.assertIsInstance(result, ReverseImageSearchResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.matches_found, 1)
        self.assertEqual(result.matches[0].page_url, "http://example.com/page")

    async def test_reverse_image_search_upload_fails(self):
        """Tests error handling when the image upload fails."""
        with patch("chimera_intel.core.media_analyzer.sync_client.post") as mock_post:
            mock_post.side_effect = Exception("Upload failed")
            with patch("builtins.open", mock_open(read_data=b"imagedata")):
                result = await reverse_image_search("test.jpg")
        self.assertIsNotNone(result.error)
        self.assertIn("Upload failed", result.error)

    # --- Audio Transcription Tests ---

    @patch("chimera_intel.core.media_analyzer.sr.Recognizer")
    def test_transcribe_audio_file_success(self, mock_recognizer):
        """Tests a successful audio transcription."""
        # Arrange

        mock_rec_instance = mock_recognizer.return_value
        mock_rec_instance.recognize_whisper.return_value = "This is a test transcript."

        with patch("chimera_intel.core.media_analyzer.sr.AudioFile"):
            # Act

            result = transcribe_audio_file("test.wav")
        # Assert

        self.assertIsInstance(result, MediaAnalysisResult)
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.transcript)
        self.assertEqual(result.transcript.text, "This is a test transcript.")

    @patch("chimera_intel.core.media_analyzer.sr.Recognizer")
    def test_transcribe_audio_file_failure(self, mock_recognizer):
        """Tests error handling during audio transcription."""
        # Arrange

        mock_rec_instance = mock_recognizer.return_value
        mock_rec_instance.recognize_whisper.side_effect = Exception("Whisper failed")

        with patch("chimera_intel.core.media_analyzer.sr.AudioFile"):
            # Act

            result = transcribe_audio_file("test.wav")
        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("Whisper failed", result.error)

    # --- CLI Tests ---

    @patch(
        "chimera_intel.core.media_analyzer.reverse_image_search", new_callable=AsyncMock
    )
    def test_cli_reverse_search_success(self, mock_reverse_search):
        """Tests the 'media reverse-search' CLI command."""
        # Arrange

        mock_reverse_search.return_value = ReverseImageSearchResult(
            source_image_path="test.jpg", matches_found=1
        )

        # Act

        result = runner.invoke(media_app, ["reverse-search", "test.jpg"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["source_image_path"], "test.jpg")
        self.assertEqual(output["matches_found"], 1)

    @patch("chimera_intel.core.media_analyzer.transcribe_audio_file")
    def test_cli_transcribe_success(self, mock_transcribe):
        """Tests the 'media transcribe' CLI command."""
        # Arrange

        mock_transcribe.return_value = MediaAnalysisResult(
            file_path="test.mp3",
            transcript=MediaTranscript(
                text="hello world", language="english", confidence=1.0
            ),
        )

        # Act

        result = runner.invoke(media_app, ["transcribe", "test.mp3"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["file_path"], "test.mp3")
        self.assertEqual(output["transcript"]["text"], "hello world")


if __name__ == "__main__":
    unittest.main()
