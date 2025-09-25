import unittest
from unittest.mock import patch, MagicMock, mock_open

from chimera_intel.core.podcast_osint import (
    find_podcast_info,
    search_in_podcast_episode,
    analyze_podcast_episode,
)
from chimera_intel.core.schemas import (
    PodcastInfoResult,
    PodcastSearchResult,
    PodcastAnalysisResult,
    MediaAnalysisResult,
    MediaTranscript,
    SWOTAnalysisResult,
)


class TestPodcastOsint(unittest.TestCase):
    """Test cases for the Podcast OSINT module."""

    @patch("chimera_intel.core.podcast_osint.feedparser.parse")
    def test_find_podcast_info_success(self, mock_feedparser):
        """Tests a successful parsing of a podcast RSS feed."""
        # Arrange: Mock the feedparser library's return value

        mock_feed = MagicMock()
        mock_feed.bozo = 0
        mock_feed.feed.get.side_effect = lambda key: {
            "title": "Test Podcast",
            "author": "Host",
        }.get(key)

        mock_entry = MagicMock()
        mock_entry.get.side_effect = lambda key, default=None: {
            "title": "Episode 1",
            "published": "Tue, 23 Sep 2025 18:00:00 +0000",
            "summary": "A test episode.",
            "links": [{"rel": "enclosure", "href": "http://example.com/ep1.mp3"}],
        }.get(key, default)

        mock_feed.entries = [mock_entry]
        mock_feedparser.return_value = mock_feed

        # Act

        result = find_podcast_info("http://example.com/feed.rss")

        # Assert

        self.assertIsInstance(result, PodcastInfoResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.title, "Test Podcast")
        self.assertEqual(len(result.episodes), 1)
        self.assertEqual(result.episodes[0].title, "Episode 1")
        self.assertEqual(result.episodes[0].audio_url, "http://example.com/ep1.mp3")

    @patch("chimera_intel.core.podcast_osint.os.path.exists", return_value=True)
    @patch("chimera_intel.core.podcast_osint.os.remove")
    @patch("chimera_intel.core.podcast_osint.sync_client")
    @patch("chimera_intel.core.podcast_osint.transcribe_audio_file")
    def test_search_in_podcast_episode_found(
        self, mock_transcribe, mock_sync_client, mock_remove, mock_exists
    ):
        """Tests a successful search within a podcast episode where the keyword is found."""
        # Arrange
        # Mock the download process

        mock_response = MagicMock()
        mock_response.iter_bytes.return_value = [b"audio_chunk"]
        mock_sync_client.stream.return_value.__enter__.return_value = mock_response

        # Mock the transcription result

        transcript = MediaTranscript(
            language="english",
            text="This is a test transcript with a special keyword.",
            confidence=1.0,
        )
        mock_transcribe.return_value = MediaAnalysisResult(
            file_path="", media_type="Audio", transcript=transcript
        )

        with patch("builtins.open", mock_open()):
            # Act

            result = search_in_podcast_episode("http://example.com/ep1.mp3", "keyword")
        # Assert

        self.assertIsInstance(result, PodcastSearchResult)
        self.assertTrue(result.is_found)
        self.assertIn("special keyword", result.transcript_snippet)
        self.assertIsNone(result.error)
        mock_remove.assert_called()  # Verify cleanup

    @patch("chimera_intel.core.podcast_osint.os.path.exists", return_value=True)
    @patch("chimera_intel.core.podcast_osint.os.remove")
    @patch("chimera_intel.core.podcast_osint.sync_client")
    @patch("chimera_intel.core.podcast_osint.transcribe_audio_file")
    @patch("chimera_intel.core.podcast_osint.generate_swot_from_data")
    @patch(
        "chimera_intel.core.podcast_osint.API_KEYS.google_api_key", "fake_google_key"
    )
    def test_analyze_podcast_episode_success(
        self,
        mock_ai_generate,
        mock_transcribe,
        mock_sync_client,
        mock_remove,
        mock_exists,
    ):
        """Tests a successful AI analysis of a podcast episode."""
        # Arrange
        # Mock download and transcription

        mock_response = MagicMock()
        mock_response.iter_bytes.return_value = [b"audio_chunk"]
        mock_sync_client.stream.return_value.__enter__.return_value = mock_response
        transcript = MediaTranscript(
            language="english", text="This is the full transcript.", confidence=1.0
        )
        mock_transcribe.return_value = MediaAnalysisResult(
            file_path="", media_type="Audio", transcript=transcript
        )

        # Mock the AI analysis result

        mock_ai_generate.return_value = SWOTAnalysisResult(
            analysis_text="## Executive Summary\nThis is an AI summary."
        )

        with patch("builtins.open", mock_open()):
            # Act

            result = analyze_podcast_episode("http://example.com/ep1.mp3")
        # Assert

        self.assertIsInstance(result, PodcastAnalysisResult)
        self.assertIsNone(result.error)
        self.assertIn("Executive Summary", result.analysis_text)
        mock_ai_generate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
