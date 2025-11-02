"""
Unit tests for the 'counter_intelligence' module.
"""

import unittest
from unittest.mock import MagicMock, patch, AsyncMock

from chimera_intel.core.counter_intelligence import (
    search_collection_infrastructure,
    score_insider_threat,
    track_media_manipulation,
    counter_intel_app,
    APT_METHODOLOGIES_DB
)
from chimera_intel.core.schemas import (
    InfraSearchResult,
    InsiderThreatResult,
    MediaProvenanceResult,
    GitHubLeaksResult,
    PasteResult
)
from typer.testing import CliRunner

runner = CliRunner()


class TestCounterIntelligence(unittest.TestCase):
    """Test cases for advanced counter-intelligence functions."""

    @patch("chimera_intel.core.counter_intelligence.API_KEYS.shodan_api_key", "fake_key")
    @patch("shodan.Shodan")
    def test_search_collection_infrastructure_found(self, mock_shodan_cls):
        """Tests infrastructure search for a positive match."""
        mock_api = mock_shodan_cls.return_value
        mock_api.search.return_value = {
            "matches": [
                {"ip_str": "1.2.3.4", "org": "TestCloud", "port": 3389, "data": "banner..."}
            ]
        }
        
        result = search_collection_infrastructure(
            client_asset="asn:AS123", apt_methodologies=["open-rdp"]
        )
        self.assertIsInstance(result, InfraSearchResult)
        self.assertEqual(result.total_found, 1)
        self.assertEqual(result.matched_patterns[0].pattern_name, "Exposed RDP")
        self.assertEqual(result.matched_patterns[0].indicator, "1.2.3.4")
        
        expected_query = f'{APT_METHODOLOGIES_DB["open-rdp"]["query"]} asn:AS123'
        mock_api.search.assert_called_with(expected_query, limit=50)

    @patch("chimera_intel.core.counter_intelligence.API_KEYS.shodan_api_key", None)
    def test_search_collection_infrastructure_no_key(self):
        """Tests infrastructure search with no Shodan key."""
        result = search_collection_infrastructure("asn:AS123", ["open-rdp"])
        self.assertIsNotNone(result.error)
        self.assertIn("Shodan API key not found", result.error)

    @patch("chimera_intel.core.counter_intelligence.search_pastes_api")
    @patch("chimera_intel.core.counter_intelligence.search_github_leaks")
    @patch("chimera_intel.core.counter_intelligence.API_KEYS.github_pat", "fake_key")
    def test_score_insider_threat(self, mock_search_github, mock_search_pastes):
        """Tests the insider threat scoring function."""
        # Setup mocks
        mock_search_github.return_value = GitHubLeaksResult(total_count=1, items=[])
        mock_search_pastes.return_value = PasteResult(pastes=[], count=0)
        
        ids = ["john.doe@example.com", "jane.smith@example.com"]
        result = score_insider_threat(ids, use_internal_signals=True)
        
        self.assertIsInstance(result, InsiderThreatResult)
        self.assertEqual(result.total_personnel_analyzed, 2)
        # john.doe@example.com (github only)
        self.assertAlmostEqual(result.personnel_scores[0].risk_score, 0.4)
        self.assertIn("GitHub", result.personnel_scores[0].key_factors[0])
        # jane.smith@example.com (no results)
        self.assertAlmostEqual(result.personnel_scores[1].risk_score, 0.0)

    @patch("chimera_intel.core.counter_intelligence.search_google")
    @patch("chimera_intel.core.counter_intelligence._get_media_fingerprint", new_callable=AsyncMock)
    def test_track_media_manipulation_article(self, mock_get_fingerprint, mock_search_google):
        """Tests media tracking for a known malicious article."""
        
        # 1. Mock fingerprinting
        mock_get_fingerprint.return_value = ('"Fake News Title"', "article", None)
        
        # 2. Mock Google Search
        class MockSearchResult:
            def __init__(self, url, snippet):
                self.url = url
                self.snippet = snippet
                
        mock_search_google.return_value = [
            MockSearchResult("http://origin-forum.com/post1", "This is the first post..."),
            MockSearchResult("http://twitter.com/user/123", "RT @Origin: This is the first post...")
        ]
        
        url = "http://fake-news.com/article123"
        result = track_media_manipulation(url)
        
        self.assertIsInstance(result, MediaProvenanceResult)
        self.assertIsNotNone(result.origin_vector)
        self.assertEqual(result.media_type, "article")
        self.assertEqual(result.media_fingerprint, '"Fake News Title"')
        self.assertEqual(result.origin_vector.platform, "origin-forum.com")
        self.assertEqual(len(result.spread_path), 1)
        self.assertEqual(result.spread_path[0].platform, "twitter.com")
        mock_search_google.assert_called_with('"Fake News Title"', num_results=20)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.counter_intelligence.search_collection_infrastructure")
    @patch("chimera_intel.core.counter_intelligence.save_or_print_results")
    @patch("chimera_intel.core.counter_intelligence.save_scan_to_db")
    def test_cli_infra_check(self, mock_save_db, mock_print, mock_search):
        """Tests the 'infra-check' CLI command."""
        mock_search.return_value = InfraSearchResult(client_asset="asn:AS123", total_found=0)
        result = runner.invoke(counter_intel_app, ["infra-check", "asn:AS123", "--apt-list", "open-rdp"])
        self.assertEqual(result.exit_code, 0)
        mock_search.assert_called_with("asn:AS123", ["open-rdp"])
        mock_print.assert_called_once()

    @patch("chimera_intel.core.counter_intelligence.score_insider_threat")
    @patch("chimera_intel.core.counter_intelligence.save_or_print_results")
    @patch("chimera_intel.core.counter_intelligence.save_scan_to_db")
    def test_cli_insider_score(self, mock_save_db, mock_print, mock_score):
        """Tests the 'insider-score' CLI command."""
        mock_score.return_value = InsiderThreatResult(total_personnel_analyzed=1, high_risk_count=0)
        result = runner.invoke(counter_intel_app, ["insider-score", "test@example.com", "--internal"])
        self.assertEqual(result.exit_code, 0)
        mock_score.assert_called_with(["test@example.com"], True)
        mock_print.assert_called_once()


if __name__ == "__main__":
    unittest.main()