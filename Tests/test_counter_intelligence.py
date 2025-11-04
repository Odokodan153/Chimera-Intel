"""
Unit tests for the 'counter_intelligence' module.
Now covers real local functions (file scan, ocr, dns, web server) with mocks.
"""

import unittest
from unittest.mock import MagicMock, patch, AsyncMock, call
import os
import json
import shutil
import dns.resolver
import dns.exception

from chimera_intel.core.counter_intelligence import (
    search_collection_infrastructure,
    score_insider_threat,
    track_media_manipulation,
    monitor_impersonation,
    deploy_honey_asset,
    get_legal_escalation_template,
    counter_intel_app
)
from chimera_intel.core.schemas import (
    InfraSearchResult,
    InsiderThreatResult,
    MediaProvenanceResult,
    DomainMonitoringResult,
    HoneyAssetResult,
    LegalTemplateResult,
    GitHubLeaksResult,
    PasteResult
)
from typer.testing import CliRunner
from PIL import Image

runner = CliRunner()

# Mock SearchResult class for google_search
class MockSearchResult:
    def __init__(self, url, snippet):
        self.url = url
        self.snippet = snippet

# Mock DNS resolve answer
class MockDNSAnswer:
    pass

class TestCounterIntelligence(unittest.TestCase):
    """Test cases for advanced counter-intelligence functions."""

    def setUp(self):
        # Create a dummy image for deploy_honey_asset test
        self.dummy_image_path = "test_source_image.png"
        Image.new("RGB", (100, 100)).save(self.dummy_image_path)
        self.honey_dir = "honey_assets"

    def tearDown(self):
        if os.path.exists(self.dummy_image_path):
            os.remove(self.dummy_image_path)
        if os.path.exists(self.honey_dir):
            shutil.rmtree(self.honey_dir)

    @patch("chimera_intel.core.counter_intelligence._load_counter_intel_data")
    @patch("chimera_intel.core.counter_intelligence.API_KEYS.shodan_api_key", "fake_key")
    @patch("shodan.Shodan")
    def test_search_collection_infrastructure_found(self, mock_shodan_cls, mock_load_data):
        """Tests infrastructure search for a positive match."""
        mock_api = mock_shodan_cls.return_value
        mock_api.search.return_value = {
            "matches": [
                {"ip_str": "1.2.3.4", "org": "TestCloud", "port": 3389, "data": "banner..."}
            ]
        }
        test_db_data = {
            "open-rdp": {
                "query": 'port:3389 "Authentication: SUCCESSFUL"',
                "confidence": 0.3,
                "pattern_name": "Exposed RDP"
            }
        }
        mock_load_data.return_value = test_db_data
        
        result = search_collection_infrastructure(
            client_asset="asn:AS123", apt_methodologies=["open-rdp"]
        )
        self.assertIsInstance(result, InfraSearchResult)
        self.assertEqual(result.total_found, 1)
        self.assertEqual(result.matched_patterns[0].pattern_name, "Exposed RDP")
        mock_load_data.assert_called_with("apt_methodologies")
        expected_query = f'{test_db_data["open-rdp"]["query"]} asn:AS123'
        mock_api.search.assert_called_with(expected_query, limit=50)

    @patch("chimera_intel.core.counter_intelligence._check_local_file_system_leaks")
    @patch("chimera_intel.core.counter_intelligence.search_google")
    @patch("chimera_intel.core.counter_intelligence.search_pastes_api")
    @patch("chimera_intel.core.counter_intelligence.search_github_leaks")
    @patch("chimera_intel.core.counter_intelligence.API_KEYS.github_pat", "fake_key")
    def test_score_insider_threat_all_signals(self, mock_search_github, mock_search_pastes, mock_search_google, mock_check_local):
        """Tests insider threat scoring with public and 'internal' (local) signals."""
        # Setup mocks
        mock_search_github.return_value = GitHubLeaksResult(total_count=1, items=[])
        mock_search_pastes.return_value = PasteResult(pastes=[], count=1)
        mock_search_google.return_value = [MockSearchResult("http://bad-blog.com", "complaint")]
        mock_check_local.return_value = ["/Users/test/Documents/leak.txt"]
        
        ids = ["john.doe@example.com"]
        result = score_insider_threat(ids, use_internal_signals=True)
        
        self.assertIsInstance(result, InsiderThreatResult)
        self.assertEqual(result.total_personnel_analyzed, 1)
        score = result.personnel_scores[0]
        
        # Risk score should be capped at 1.0
        # 0.4 (github) + 0.6 (paste) + 0.2 (sentiment) + 0.5 (local) = 1.7, capped at 1.0
        self.assertAlmostEqual(score.risk_score, 1.0)
        self.assertEqual(len(score.key_factors), 4)
        self.assertIn("GitHub", score.key_factors[0])
        self.assertIn("Paste.ee", score.key_factors[1])
        self.assertIn("sentiment", score.key_factors[2])
        self.assertIn("local workstation", score.key_factors[3])
        
        mock_check_local.assert_called_with("john.doe@example.com")
        mock_search_google.assert_called_once()

    @patch("glob.glob")
    @patch("os.path.exists")
    def test_check_local_file_system_leaks(self, mock_exists, mock_glob):
        """Tests the real local file system scanner function (mocked)."""
        from chimera_intel.core.counter_intelligence import _check_local_file_system_leaks
        
        mock_exists.return_value = True # Assume /Users/test/Documents exists
        mock_glob.return_value = ["/Users/test/Documents/test.txt"]
        
        # Mock open()
        m = unittest.mock.mock_open(read_data="This file contains jdoe@example.com sensitive data")
        with patch("builtins.open", m):
            results = _check_local_file_system_leaks("jdoe@example.com")
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], "/Users/test/Documents/test.txt")

    @patch("chimera_intel.core.counter_intelligence.pytesseract.image_to_string")
    @patch("chimera_intel.core.counter_intelligence.search_google")
    @patch("chimera_intel.core.counter_intelligence.sync_client.get", new_callable=AsyncMock)
    def test_track_media_manipulation_ocr(self, mock_get, mock_search_google, mock_ocr):
        """Tests media tracking using the new OCR fingerprint."""
        # Mock the HTTP response for an image
        mock_response = MagicMock()
        mock_response.headers = {"content-type": "image/png"}
        mock_response.content = b"fake image data"
        mock_get.return_value = mock_response
        
        # Mock OCR output
        ocr_text = "This is secret text from an image"
        mock_ocr.return_value = ocr_text
        
        mock_search_google.return_value = [
            MockSearchResult("http://origin-forum.com/post1", "This is secret text..."),
        ]
        
        url = "http://fake-news.com/image.png"
        result = track_media_manipulation(url)
        
        self.assertIsInstance(result, MediaProvenanceResult)
        self.assertEqual(result.media_type, "image_ocr")
        self.assertEqual(result.media_fingerprint, f'"{ocr_text}"')
        self.assertEqual(result.origin_vector.platform, "origin-forum.com")
        mock_search_google.assert_called_with(f'"{ocr_text}"', num_results=20)

    @patch("dns.resolver.Resolver")
    @patch("chimera_intel.core.counter_intelligence.search_google")
    def test_monitor_impersonation_real_dns_and_filter(self, mock_search_google, mock_resolver_cls):
        """Tests domain watch with real DNS (mocked) and official URL filtering."""
        mock_resolver = mock_resolver_cls.return_value
        
        # Mock DNS checks: one domain resolves (bad), others don't (good)
        def mock_resolve_logic(domain, rdtype):
            if domain == "chimera-inte1.com": # The '1' homoglyph
                return MockDNSAnswer() # It resolves, it's a threat
            raise dns.resolver.NXDOMAIN # All others don't exist

        mock_resolver.resolve = MagicMock(side_effect=mock_resolve_logic)
        
        # Mock Google Search for social
        mock_search_google.return_value = [
            MockSearchResult("http://twitter.com/chimera_intel", "Official Account"), # This one should be filtered
            MockSearchResult("http://twitter.com/chimera_intel_scam", "Scam Account") # This one should be reported
        ]
        
        official_urls = ["http://twitter.com/chimera_intel"]
        
        result = monitor_impersonation(
            base_domain="chimera-intel.com",
            brand_name="Chimera Intel",
            official_social_urls=official_urls,
            check_permutations=True # Enable DNS check
        )
        
        self.assertIsInstance(result, DomainMonitoringResult)
        # Asserts that the DNS-resolved domain was found
        self.assertEqual(len(result.lookalikes_found), 1)
        self.assertIn("chimera-inte1.com", result.lookalikes_found[0]) 
        # Asserts that only the *non-official* social account was reported
        self.assertEqual(len(result.impersonator_accounts), 1)
        self.assertEqual(result.impersonator_accounts[0]["url"], "http://twitter.com/chimera_intel_scam")
        
        # Check that DNS resolver was called for permutations
        self.assertGreater(mock_resolver.resolve.call_count, 1)

    @patch("threading.Thread")
    @patch("socketserver.TCPServer")
    @patch("imagehash.phash")
    @patch("PIL.ImageDraw.Draw")
    @patch("PIL.Image.Image.save")
    @patch("PIL.Image.open")
    def test_deploy_honey_asset_local_server(self, mock_img_open, mock_img_save, mock_draw, mock_phash, mock_server, mock_thread):
        """Tests honey asset deployment with the local tracking server."""
        # Mock all the image processing
        mock_img_open.return_value = MagicMock()
        mock_phash.return_value = "fake_phash_123"
        
        result = deploy_honey_asset(self.dummy_image_path, "campaign-1", port=9999)
        
        self.assertIsInstance(result, HoneyAssetResult)
        self.assertEqual(result.status, "deployed_local_tracking")
        self.assertEqual(result.asset_id, "campaign-1")
        self.assertEqual(result.fingerprint, "fake_phash_123")
        # Check that it returns the correct local server URL
        self.assertIn("http://127.0.0.1:9999/campaign-1-fake_phash_123.png", result.tracking_url)
        
        # Check that the image was "saved" to the correct local path
        expected_save_path = os.path.join(self.honey_dir, "campaign-1-fake_phash_123.png")
        mock_img_save.assert_called_with(expected_save_path, "PNG")
        
        # Check that the server was started
        mock_server.assert_called_with(("", 9999), unittest.mock.ANY)
        mock_thread.assert_called_once()

    @patch("chimera_intel.core.counter_intelligence._load_counter_intel_data")
    def test_get_legal_escalation_template(self, mock_load_data):
        """Tests retrieving a legal escalation template."""
        mock_load_data.return_value = {
            "dmca-takedown": {"template": "Test template", "contacts": ["abuse@test.com"]}
        }
        
        result = get_legal_escalation_template("dmca-takedown")
        self.assertIsInstance(result, LegalTemplateResult)
        self.assertIn("Test template", result.template_body)
        self.assertIn("abuse@test.com", result.contacts)
        mock_load_data.assert_called_with("legal_templates")

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.counter_intelligence.score_insider_threat")
    @patch("chimera_intel.core.counter_intelligence.save_or_print_results")
    @patch("chimera_intel.core.counter_intelligence.save_scan_to_db")
    def test_cli_insider_score_internal(self, mock_save_db, mock_print, mock_score):
        """Tests the 'insider-score' CLI command with the --internal flag."""
        mock_score.return_value = InsiderThreatResult(total_personnel_analyzed=1, high_risk_count=0)
        result = runner.invoke(counter_intel_app, ["insider-score", "test@example.com", "--internal"])
        
        self.assertEqual(result.exit_code, 0)
        # Verify the '--internal' flag (True) was passed correctly
        mock_score.assert_called_with(["test@example.com"], True)
        mock_print.assert_called_once()

    @patch("chimera_intel.core.counter_intelligence.monitor_impersonation")
    @patch("chimera_intel.core.counter_intelligence.save_or_print_results")
    @patch("chimera_intel.core.counter_intelligence.save_scan_to_db")
    def test_cli_domain_watch_new_flags(self, mock_save_db, mock_print, mock_monitor):
        """Tests the 'domain-watch' CLI command with new flags."""
        mock_monitor.return_value = DomainMonitoringResult(base_domain="test.com")
        
        result = runner.invoke(counter_intel_app, [
            "domain-watch", 
            "test.com", 
            "Test Inc", 
            "--official-urls", "http://twitter.com/test",
            "--no-check-permutations"
        ])
        
        self.assertEqual(result.exit_code, 0)
        mock_monitor.assert_called_with(
            "test.com", 
            "Test Inc",
            social_platforms=unittest.mock.ANY, # Default list
            official_social_urls=["http://twitter.com/test"],
            check_permutations=False # Test the 'no-' flag
        )
        mock_print.assert_called_once()

    @patch("chimera_intel.core.counter_intelligence.deploy_honey_asset")
    @patch("chimera_intel.core.counter_intelligence.save_or_print_results")
    @patch("chimera_intel.core.counter_intelligence.save_scan_to_db")
    def test_cli_honey_deploy_port(self, mock_save_db, mock_print, mock_deploy):
        """Tests the 'honey-deploy' CLI command with the --port flag."""
        mock_deploy.return_value = HoneyAssetResult(
            asset_id="test", tracking_url="http://127.0.0.1:1234/test.png"
        )
        
        result = runner.invoke(counter_intel_app, [
            "honey-deploy", 
            self.dummy_image_path, 
            "test-id", 
            "--port", "1234"
        ])
        
        self.assertEqual(result.exit_code, 0)
        mock_deploy.assert_called_with(self.dummy_image_path, "test-id", port=1234)
        mock_print.assert_called_once()

if __name__ == "__main__":
    unittest.main()