import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner

# We must patch the *assumed* module imports before they are imported
# by narrative_tracker. We mock them as AsyncMocks.
mock_web_scraper = MagicMock()
mock_web_scraper.scrape_url_text = AsyncMock(return_value="This is the full scraped text of the article about AI in supply chains.")

mock_ai_core = MagicMock()
mock_ai_core.get_summary = AsyncMock(return_value="Article discusses AI for supply chains.")

mock_topic_clusterer = MagicMock()
mock_topic_clusterer.cluster_topics = AsyncMock(return_value=[
    {
        "theme_name": "AI in Supply Chains",
        "keywords": ["ai", "supply chain", "logistics"],
        "representative_docs": [0]
    }
])

# Apply patches to the module lookup path
module_patches = {
    "chimera_intel.core.web_scraper": mock_web_scraper,
    "chimera_intel.core.ai_core": mock_ai_core,
    "chimera_intel.core.topic_clusterer": mock_topic_clusterer,
}

with patch.dict("sys.modules", module_patches):
    from chimera_intel.core.narrative_tracker import app as narrative_app
    from chimera_intel.core import narrative_tracker

runner = CliRunner()

class TestNarrativeTracker(unittest.TestCase):
    """Test cases for the Narrative Tracker module."""

    def setUp(self):
        # Reset mocks before each test
        mock_web_scraper.scrape_url_text.reset_mock()
        mock_ai_core.get_summary.reset_mock()
        mock_topic_clusterer.cluster_topics.reset_mock()

    @patch("chimera_intel.core.narrative_tracker.API_KEYS")
    @patch("chimera_intel.core.narrative_tracker.async_client.get", new_callable=AsyncMock)
    @patch("chimera_intel.core.narrative_tracker.resolve_target", return_value="competitor.com")
    def test_analyze_themes_success(
        self, mock_resolve, mock_async_get, mock_api_keys
    ):
        """Tests the full flow of the analyze-themes command."""
        # Arrange
        mock_api_keys.google_api_key = "fake_google_key"
        mock_api_keys.google_cse_id = "fake_cse_id"

        # Mock the Google CSE API response
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "items": [
                {
                    "title": "Our New Blog on AI",
                    "link": "https://competitor.com/blog/ai-supply-chain",
                    "snippet": "We talk about AI in supply chains...",
                }
            ]
        }
        mock_async_get.return_value = mock_response

        # Act
        result = runner.invoke(narrative_app, ["analyze-themes", "competitor.com"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        
        # 1. Check that Google CSE was called
        mock_async_get.assert_called_once()
        self.assertIn("site:competitor.com", mock_async_get.call_args[1]["params"]["q"])

        # 2. Check that scraper was called
        mock_web_scraper.scrape_url_text.assert_awaited_with(
            "https://competitor.com/blog/ai-supply-chain"
        )
        
        # 3. Check that summarizer was called
        mock_ai_core.get_summary.assert_awaited_with(
            "This is the full scraped text of the article about AI in supply chains."
        )

        # 4. Check that clusterer was called
        mock_topic_clusterer.cluster_topics.assert_awaited_with(
            ["This is the full scraped text of the article about AI in supply chains."],
            num_clusters=5
        )

        # 5. Check output
        self.assertIn("Identified 1 strategic themes", result.stdout)
        self.assertIn("AI in Supply Chains", result.stdout)
        self.assertIn("ai, supply chain, logistics", result.stdout)

    @patch("chimera_intel.core.narrative_tracker.API_KEYS")
    def test_analyze_themes_no_api_keys(self, mock_api_keys):
        """Tests failure when API keys are missing."""
        # Arrange
        mock_api_keys.google_api_key = None
        mock_api_keys.google_cse_id = None

        # Act
        result = runner.invoke(narrative_app, ["analyze-themes", "competitor.com"])

        # Assert
        self.assertEqual(result.exit_code, 1)
        self.assertIn("must be set", result.stdout)

if __name__ == "__main__":
    unittest.main()