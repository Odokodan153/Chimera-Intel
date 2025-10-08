import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

from chimera_intel.core.deep_research import conduct_deep_research, DeepResearchResult


class TestDeepResearch(unittest.TestCase):
    """Test cases for the sophisticated Deep Research module."""

    @patch("chimera_intel.core.deep_research.API_KEYS")
    @patch("chimera_intel.core.deep_research.genai.GenerativeModel")
    @patch("chimera_intel.core.deep_research.search", new_callable=AsyncMock)
    def test_conduct_deep_research_success(
        self, mock_search, mock_genai_model, mock_api_keys
    ):
        """
        Tests the successful execution of the entire deep research workflow.
        """
        # --- Arrange ---

        topic = "quantum computing"
        mock_api_keys.google_api_key = "fake_api_key"

        # Mock the google_search function

        mock_search.return_value = [
            MagicMock(
                results=[
                    MagicMock(
                        source_title="Overview",
                        url="http://overview.com",
                        snippet="...",
                    )
                ]
            ),
            MagicMock(
                results=[
                    MagicMock(source_title="News", url="http://news.com", snippet="...")
                ]
            ),
            MagicMock(
                results=[
                    MagicMock(source_title="Tech", url="http://tech.com", snippet="...")
                ]
            ),
        ]

        # Mock the Generative AI model's response

        mock_ai_response = MagicMock()
        mock_ai_response.text = """
        ```json
        {
          "summary": "This is a test summary about quantum computing.",
          "key_findings": [
            {
              "finding": "Quantum supremacy has been achieved.",
              "sources": ["[http://news.com](http://news.com)"]
            }
          ]
        }
        ```
        """
        mock_model_instance = MagicMock()
        mock_model_instance.generate_content.return_value = mock_ai_response
        mock_genai_model.return_value = mock_model_instance

        # --- Act ---

        result = asyncio.run(conduct_deep_research(topic))

        # --- Assert ---

        self.assertIsNotNone(result)
        self.assertIsInstance(result, DeepResearchResult)
        self.assertEqual(result.topic, topic)
        self.assertEqual(
            result.summary, "This is a test summary about quantum computing."
        )
        self.assertEqual(len(result.key_findings), 1)
        self.assertEqual(
            result.key_findings[0].finding, "Quantum supremacy has been achieved."
        )
        self.assertEqual(result.key_findings[0].sources, ["http://news.com"])

        # Verify that the external services were called correctly

        mock_search.assert_called_once()
        mock_genai_model.return_value.generate_content.assert_called_once()

    @patch("chimera_intel.core.deep_research.API_KEYS")
    def test_conduct_deep_research_no_api_key(self, mock_api_keys):
        """
        Tests that the function returns None if the API key is missing.
        """
        # --- Arrange ---

        mock_api_keys.google_api_key = None

        # --- Act ---

        result = asyncio.run(conduct_deep_research("any topic"))

        # --- Assert ---

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
