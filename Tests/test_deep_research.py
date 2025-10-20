import unittest
import json
import asyncio
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.deep_research import conduct_deep_research, deep_research_app
from chimera_intel.core.schemas import (
    DeepResearchReport,
    KnowledgeGraph,
    TargetProfile,
    PESTAnalysis,
)


runner = CliRunner()


class TestDeepResearch(unittest.TestCase):
    """Test cases for the Deep Research module."""

    @patch("chimera_intel.core.deep_research.API_KEYS")
    @patch("chimera_intel.core.deep_research.genai")
    @patch("chimera_intel.core.deep_research.search")
    def test_conduct_deep_research_success(
        self,
        mock_search,
        mock_genai,
        mock_api_keys,
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
                        "reference": "http://example.com/some-finding",
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

        mock_genai.GenerativeModel.return_value = mock_model_instance
        mock_genai.configure = MagicMock()

        # --- Act ---

        result = asyncio.run(conduct_deep_research(topic))

        # --- Assert ---

        self.assertIsInstance(result, DeepResearchReport)
        self.assertEqual(result.target_profile.name, "Quantum Computing")
        self.assertEqual(len(result.intelligence_findings), 1)
        self.assertEqual(
            result.intelligence_findings[0].summary,
            "Breakthrough in qubit stability.",
        )
        self.assertEqual(
            result.intelligence_findings[0].reference,
            "http://example.com/some-finding",
        )
        self.assertEqual(result.pest_analysis.political[0], "Government funding")
        self.assertIn("Quantum Computing", result.knowledge_graph.nodes[0].id)
        mock_search.assert_called_once_with(topic)
        mock_genai.configure.assert_called_once_with(api_key="fake_api_key")

    @patch("chimera_intel.core.deep_research.API_KEYS")
    @patch("chimera_intel.core.deep_research.genai")
    @patch("chimera_intel.core.deep_research.search")
    def test_conduct_deep_research_json_error(
        self,
        mock_search,
        mock_genai,
        mock_api_keys,
    ):
        """
        Tests handling of invalid JSON output from the AI model.
        """
        # --- Arrange ---

        topic = "invalid json test"
        mock_api_keys.google_api_key = "fake_api_key"
        mock_search.return_value = ["http://example.com/1"]

        mock_ai_response = MagicMock()
        mock_ai_response.text = "This is not valid JSON."
        mock_model_instance = MagicMock()
        mock_model_instance.generate_content.return_value = mock_ai_response

        mock_genai.GenerativeModel.return_value = mock_model_instance
        mock_genai.configure = MagicMock()

        # --- Act ---

        result = asyncio.run(conduct_deep_research(topic))

        # --- Assert ---

        self.assertIsNone(result)

    @patch("chimera_intel.core.deep_research.API_KEYS")
    def test_conduct_deep_research_no_api_key(self, mock_api_keys):
        """
        Tests that the function returns None if the API key is missing.
        """
        # --- Arrange ---

        mock_api_keys.google_api_key = None

        # --- Act ---

        result = asyncio.run(conduct_deep_research("test"))

        # --- Assert ---

        self.assertIsNone(result)

    # --- CLI Tests ---

    @patch(
        "chimera_intel.core.deep_research.conduct_deep_research",
    )
    def test_cli_run_success(self, mock_conduct_research):
        """Tests a successful run of the 'deep-research run' CLI command."""
        # Arrange

        # Must use asyncio.Future for async mocks called by sync CLI
        mock_future = asyncio.Future()
        mock_future.set_result(
            DeepResearchReport(
                target_profile=TargetProfile(name="Test Topic", description="A test."),
                strategic_summary="Summary",
                pest_analysis=PESTAnalysis(),
                intelligence_gaps=[],
                recommended_actions=[],
                intelligence_findings=[],
                knowledge_graph=KnowledgeGraph(nodes=[], edges=[]),
            )
        )
        mock_conduct_research.return_value = mock_future

        # Act

        result = runner.invoke(deep_research_app, ["run", "Test Topic"])

        # Assert

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Deep Research Report for: Test Topic", result.stdout)
        self.assertIn("Strategic Summary", result.stdout)

    @patch(
        "chimera_intel.core.deep_research.conduct_deep_research",
    )
    def test_cli_run_failure(self, mock_conduct_research):
        """Tests a failed run of the 'deep-research run' CLI command."""
        # Arrange

        mock_future = asyncio.Future()
        mock_future.set_result(None)  # Simulate a failure
        mock_conduct_research.return_value = mock_future

        # Act

        result = runner.invoke(deep_research_app, ["run", "Failed Topic"])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Failed to conduct deep research", result.stdout)

    def test_cli_run_no_topic(self):
        """Tests that the CLI command fails if no topic is provided."""
        result = runner.invoke(deep_research_app, ["run"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Missing argument 'TOPIC'", result.stderr)


if __name__ == "__main__":
    unittest.main()