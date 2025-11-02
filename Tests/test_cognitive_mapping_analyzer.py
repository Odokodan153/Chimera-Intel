import unittest
import json
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

# Import the components from the (now real) analyzer
from chimera_intel.core.cognitive_mapping_analyzer import (
    generate_cognitive_map,
    cognitive_mapping_app,
    CognitiveMapResult,
    MentalModelVector
)
from chimera_intel.core.config_loader import API_KEYS

runner = CliRunner()

# A realistic mock JSON response from the Gemini client
MOCK_AI_RESPONSE = json.dumps({
    "cognitive_model_summary": "John Doe exhibits a strong focus on innovation, often viewing market challenges as opportunities for disruption.",
    "predictive_assessment": "In a crisis, Doe would likely double-down on new technology rather than retreat to core safety.",
    "key_vectors": [
        {
            "vector_type": "Core Value",
            "description": "Prioritizes rapid innovation over stability",
            "evidence_snippet": "We must innovate or we will be left behind."
        },
        {
            "vector_type": "Decision-Making Bias",
            "description": "Optimism Bias",
            "evidence_snippet": "Our new product will capture 50% of the market, I'm sure of it."
        }
    ]
})


class TestCognitiveMappingAnalyzer(unittest.TestCase):

    @patch("chimera_intel.core.cognitive_mapping_analyzer.track_narrative")
    @patch("chimera_intel.core.cognitive_mapping_analyzer.gemini_client.generate_response")
    @patch.object(API_KEYS, "google_api_key", "fake_key") # Mock API key directly
    def test_generate_cognitive_map_success(
        self, mock_gemini_response, mock_track_narrative
    ):
        """Tests successful cognitive map generation with valid AI JSON response."""
        # Arrange
        mock_track_narrative.return_value = [
            {"title": "Test Speech", "content": "I believe in innovation."}
        ]
        mock_gemini_response.return_value = MOCK_AI_RESPONSE

        # Act
        result = generate_cognitive_map("John Doe")

        # Assert
        self.assertIsInstance(result, CognitiveMapResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.person_name, "John Doe")
        
        # Test that fields are parsed from JSON
        self.assertIn("strong focus on innovation", result.cognitive_model_summary)
        self.assertIn("double-down on new technology", result.predictive_assessment)
        
        self.assertEqual(len(result.key_vectors), 2)
        self.assertIsInstance(result.key_vectors[0], MentalModelVector)
        self.assertEqual(result.key_vectors[0].vector_type, "Core Value")
        self.assertEqual(result.key_vectors[0].description, "Prioritizes rapid innovation over stability")
        self.assertEqual(result.key_vectors[1].vector_type, "Decision-Making Bias")
        
        mock_track_narrative.assert_called_with("John Doe", limit=15)
        mock_gemini_response.assert_called_once()

    @patch("chimera_intel.core.cognitive_mapping_analyzer.track_narrative")
    def test_generate_cognitive_map_no_data(self, mock_track_narrative):
        """Tests cognitive map generation when no data is found."""
        # Arrange
        mock_track_narrative.return_value = []

        # Act
        result = generate_cognitive_map("Jane Doe")

        # Assert
        self.assertIsInstance(result, CognitiveMapResult)
        self.assertIsNotNone(result.error)
        self.assertIn("No public communications found", result.error)

    @patch("chimera_intel.core.cognitive_mapping_analyzer.track_narrative")
    @patch("chimera_intel.core.cognitive_mapping_analyzer.gemini_client.generate_response")
    @patch.object(API_KEYS, "google_api_key", "fake_key")
    def test_generate_cognitive_map_ai_empty_response(
        self, mock_gemini_response, mock_track_narrative
    ):
        """Tests cognitive map generation when AI returns an empty response."""
        # Arrange
        mock_track_narrative.return_value = [
            {"title": "Test Speech", "content": "I believe in innovation."}
        ]
        mock_gemini_response.return_value = None # Simulate empty response

        # Act
        result = generate_cognitive_map("John Doe")

        # Assert
        self.assertIsInstance(result, CognitiveMapResult)
        self.assertIsNotNone(result.error)
        self.assertIn("AI analysis failed (empty response)", result.error)

    @patch("chimera_intel.core.cognitive_mapping_analyzer.track_narrative")
    @patch("chimera_intel.core.cognitive_mapping_analyzer.gemini_client.generate_response")
    @patch.object(API_KEYS, "google_api_key", "fake_key")
    def test_generate_cognitive_map_ai_invalid_json(
        self, mock_gemini_response, mock_track_narrative
    ):
        """Tests cognitive map generation when AI returns invalid JSON."""
        # Arrange
        mock_track_narrative.return_value = [
            {"title": "Test Speech", "content": "I believe in innovation."}
        ]
        mock_gemini_response.return_value = "This is not valid JSON."

        # Act
        result = generate_cognitive_map("John Doe")

        # Assert
        self.assertIsInstance(result, CognitiveMapResult)
        self.assertIsNotNone(result.error)
        self.assertIn("AI response was not valid JSON", result.error)

    @patch.object(API_KEYS, "google_api_key", None) # No API key
    def test_generate_cognitive_map_no_api_key(self):
        """Tests that an error is returned if the API key is not configured."""
        # Act
        result = generate_cognitive_map("John Doe")

        # Assert
        self.assertIsInstance(result, CognitiveMapResult)
        self.assertIsNotNone(result.error)
        self.assertIn("Google API key not configured", result.error)

    @patch("chimera_intel.core.cognitive_mapping_analyzer.generate_cognitive_map")
    @patch("chimera_intel.core.cognitive_mapping_analyzer.save_or_print_results")
    @patch("chimera_intel.core.cognitive_mapping_analyzer.save_scan_to_db")
    def test_cli_cognitive_mapping_run_success(
        self, mock_save_db, mock_save_print, mock_generate
    ):
        """Tests the 'run' CLI command for cognitive-mapping."""
        # Arrange
        mock_dump_dict = {"person_name": "John Doe", "key_vectors": [{"description": "test"}]}
        # Create a mock result object that mimics the Pydantic model
        mock_result = MagicMock(spec=CognitiveMapResult)
        mock_result.model_dump.return_value = mock_dump_dict
        mock_result.error = None # Indicate success
        mock_generate.return_value = mock_result

        # Act
        result = runner.invoke(cognitive_mapping_app, ["run", "John Doe"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        mock_generate.assert_called_with("John Doe")
        mock_save_print.assert_called_with(mock_dump_dict, None)
        # Verify it saves to DB only on success
        mock_save_db.assert_called_with(
            target="John Doe", module="cognitive_mapping", data=mock_dump_dict
        )

    @patch("chimera_intel.core.cognitive_mapping_analyzer.generate_cognitive_map")
    @patch("chimera_intel.core.cognitive_mapping_analyzer.save_or_print_results")
    @patch("chimera_intel.core.cognitive_mapping_analyzer.save_scan_to_db")
    def test_cli_cognitive_mapping_run_error(
        self, mock_save_db, mock_save_print, mock_generate
    ):
        """Tests that the CLI handles an error from the main function."""
        # Arrange
        mock_dump_dict = {"person_name": "John Doe", "error": "Test error"}
        mock_result = MagicMock(spec=CognitiveMapResult)
        mock_result.model_dump.return_value = mock_dump_dict
        mock_result.error = "Test error" # Indicate failure
        mock_generate.return_value = mock_result

        # Act
        result = runner.invoke(cognitive_mapping_app, ["run", "John Doe"])

        # Assert
        self.assertEqual(result.exit_code, 0) # CLI itself doesn't fail
        mock_generate.assert_called_with("John Doe")
        mock_save_print.assert_called_with(mock_dump_dict, None)
        # Verify it does NOT save to DB on error
        mock_save_db.assert_not_called()
        self.assertIn("Error: Test error", result.stdout)


if __name__ == "__main__":
    unittest.main()