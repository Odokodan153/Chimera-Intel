"""
Unit tests for the 'attribution' module.
"""

import unittest
from unittest.mock import patch
import json

from chimera_intel.core.attribution import (
    score_attribution_confidence,
    attribution_app,
    THREAT_ACTOR_DB
)
from chimera_intel.core.schemas import AttributionScoreResult
from typer.testing import CliRunner

runner = CliRunner()


class TestAttribution(unittest.TestCase):
    """Test cases for attribution scoring functions."""

    def test_score_attribution_confidence_success(self):
        """Tests a successful attribution scoring calculation."""
        indicators = [
            {"type": "TTP", "id": "T1059.001", "weight": 1.0}, # Matches APT-42 (0.8)
            {"type": "TTP", "id": "T1566.001", "weight": 0.5}, # Matches APT-42 (0.7)
            {"type": "TTP", "id": "T9999", "weight": 1.0}      # Unknown
        ]
        
        # Score = (0.8 * 1.0) + (0.7 * 0.5) = 0.8 + 0.35 = 1.15
        # Weight = 1.0 + 0.5 = 1.5
        # Final Score = 1.15 / 1.5 = 0.766...
        
        result = score_attribution_confidence("APT-42", indicators, THREAT_ACTOR_DB)
        self.assertIsInstance(result, AttributionScoreResult)
        self.assertEqual(result.proposed_actor, "APT-42")
        self.assertAlmostEqual(result.confidence_score, 1.15 / 1.5)
        self.assertEqual(len(result.matched_indicators), 2)
        self.assertEqual(len(result.conflicting_indicators), 0)
        self.assertEqual(len(result.unknown_indicators), 1)

    def test_score_attribution_confidence_conflict(self):
        """Tests scoring with a conflicting TTP."""
        indicators = [
            {"type": "TTP", "id": "T1059.001", "weight": 1.0}, # Matches APT-42 (0.8)
            {"type": "TTP", "id": "T1486", "weight": 1.0}      # Matches WizardSpider (Conflicting)
        ]
        
        # Score = (0.8 * 1.0) = 0.8
        # Weight = 1.0
        # Final Score = 0.8 / 1.0 = 0.8
        
        result = score_attribution_confidence("APT-42", indicators, THREAT_ACTOR_DB)
        self.assertAlmostEqual(result.confidence_score, 0.8)
        self.assertEqual(len(result.matched_indicators), 1)
        self.assertEqual(len(result.conflicting_indicators), 1)
        self.assertEqual(result.conflicting_indicators[0]["conflicts_with"], "WizardSpider")

    def test_score_attribution_actor_not_found(self):
        """Tests scoring for an actor not in the DB."""
        indicators = [{"type": "TTP", "id": "T1059.001", "weight": 1.0}]
        result = score_attribution_confidence("APT-UNKNOWN", indicators, THREAT_ACTOR_DB)
        self.assertEqual(result.confidence_score, 0.0)
        self.assertIsNotNone(result.error)
        self.assertIn("not found in knowledge base", result.error)
        self.assertEqual(len(result.unknown_indicators), 1)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.attribution.score_attribution_confidence")
    @patch("chimera_intel.core.attribution.save_or_print_results")
    @patch("chimera_intel.core.attribution.save_scan_to_db")
    def test_cli_score_actor(self, mock_save_db, mock_print, mock_score):
        """Tests the 'score-actor' CLI command."""
        mock_score.return_value = AttributionScoreResult(
            proposed_actor="APT-42",
            confidence_score=0.75,
            total_indicators_provided=1,
            matched_indicators=[],
            conflicting_indicators=[],
            unknown_indicators=[]
        )
        json_input = '[{"type": "TTP", "id": "T1059.001", "weight": 0.75}]'
        
        result = runner.invoke(attribution_app, ["score-actor", "APT-42", json_input])
        
        self.assertEqual(result.exit_code, 0)
        mock_score.assert_called_with("APT-42", [{"type": "TTP", "id": "T1059.001", "weight": 0.75}], THREAT_ACTOR_DB)
        mock_print.assert_called_once()

    def test_cli_score_actor_invalid_json(self):
        """Tests the 'score-actor' CLI command with invalid JSON."""
        result = runner.invoke(attribution_app, ["score-actor", "APT-42", "not-json"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Invalid JSON format", result.stdout)


if __name__ == "__main__":
    unittest.main()