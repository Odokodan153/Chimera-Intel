import unittest
import asyncio
import json
from unittest.mock import patch, MagicMock

from chimera_intel.core.deep_research import (
    conduct_deep_research,
    DeepResearchResult,
    PESTAnalysis
)


class TestDeepResearch(unittest.TestCase):
    """Test cases for the sophisticated Deep Research module."""

    @patch("chimera_intel.core.deep_research.API_KEYS")
    @patch("chimera_intel.core.deep_research.genai.GenerativeModel")
    @patch("chimera_intel.core.deep_research.search")
    def test_conduct_deep_research_success(
        self, mock_search, mock_genai_model, mock_api_keys
    ):
        """
        Tests the successful execution of the entire deep research workflow.
        """
        # --- Arrange ---

        topic = "quantum computing"
        mock_api_keys.google_api_key = "fake_api_key"

        # Mock the google_search function to return a list of URLs

        mock_search.return_value = ["http://example.com/some-finding"]

        # Mock the Generative AI model's response with a valid JSON structure

        mock_ai_response = MagicMock()
        mock_ai_response.text = json.dumps(
            {
                "target_profile": {
                    "name": "Quantum Computing",
                    "description": "A new paradigm.",
                },
                "strategic_summary": "This is a strategic summary.",
                "pest_analysis": {
                    "political": ["Government funding"],
                    "economic": ["High investment costs"],
                    "social": ["Public perception"],
                    "technological": ["Rapid advancements"],
                },
                "intelligence_gaps": ["What is the current market size?"],
                "recommended_actions": ["Invest in R&D"],
                "intelligence_findings": [
                    {
                        "source_type": "TECHINT",
                        "summary": "Breakthrough in qubit stability.",
                        "risk_level": "Medium",
                        "confidence": "High",
                    }
                ],
                "knowledge_graph": {
                    "nodes": [{"id": "Quantum Computing", "type": "Field"}],
                    "edges": [],
                },
            }
        )
        mock_model_instance = MagicMock()
        mock_model_instance.generate_content.return_value = mock_ai_response
        mock_genai_model.return_value = mock_model_instance

        # --- Act ---

        result = asyncio.run(conduct_deep_research(topic))

        # --- Assert ---

        self.assertIsNotNone(result)
        self.assertIsInstance(result, DeepResearchResult)
        self.assertEqual(result.topic, topic)
        self.assertEqual(result.strategic_summary, "This is a strategic summary.")
        self.assertIsInstance(result.pest_analysis, PESTAnalysis)
        self.assertEqual(result.pest_analysis.economic, ["High investment costs"])
        self.assertEqual(len(result.intelligence_findings), 1)
        self.assertEqual(
            result.intelligence_findings[0].summary, "Breakthrough in qubit stability."
        )

        # Verify that the external services were called correctly
        # 7 gather functions, each calling search once

        self.assertEqual(mock_search.call_count, 7)
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
