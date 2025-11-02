import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
import json
import tempfile
import pathlib
import io
import numpy as np
from datetime import datetime

# Import the app to be tested
from chimera_intel.core.media_forensics import forensics_app

# Import schemas to verify output
from chimera_intel.core.media_forensics import (
    ForensicArtifactResult,
    DeepfakeAnalysisResult,
    ProvenanceResult,
    NarrativeMapResult,
    PoisoningDetectionResult,
)

runner = CliRunner()


class TestMediaForensics(unittest.TestCase):
    """
    Test cases for the Deepfake & Photoshop Forensics module.
    These tests mock the external libraries (PIL, C2PA, HTTPX, etc.)
    which is the correct way to write unit tests.
    """

    # --- Core Function Tests (Mocking Libraries) ---

    @patch("chimera_intel.core.media_forensics.Image.open")
    @patch("chimera_intel.core.media_forensics.ImageChops.difference")
    @patch("chimera_intel.core.media_forensics.ImageEnhance.Brightness")
    def test_forensic_artifact_scan_ela(self, mock_enhance, mock_diff, mock_pil_open):
        """Tests the artifact scan logic (ELA and EXIF)."""
        # Arrange
        # Mock a 'clean' image
        mock_img = MagicMock()
        mock_img.convert.return_value = mock_img
        # Mock EXIF data
        mock_img.getexif.return_value = {305: "Adobe Photoshop CS6"} # 305=Software
        
        # Mock the re-saved image (opened from buffer)
        mock_resaved_img = MagicMock()
        mock_pil_open.side_effect = [mock_img, mock_resaved_img]

        # Mock ELA image
        mock_ela_img = MagicMock()
        mock_ela_img.getextrema.return_value = [(0, 50), (0, 50), (0, 50)] # Medium diff
        mock_ela_img.convert.return_value.std.return_value = 25 # High variance
        mock_diff.return_value = mock_ela_img
            
        # Act
        from chimera_intel.core.media_forensics import forensic_artifact_scan
        result = forensic_artifact_scan(pathlib.Path("photoshop.jpg"))

        # Assert
        self.assertIsInstance(result, ForensicArtifactResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.artifacts_found), 2)
        self.assertIn("Manipulation Software (Photoshop/GIMP) in EXIF", result.artifacts_found)
        self.assertIn("High Variance Error Level Analysis (ELA)", result.artifacts_found)

    @patch("chimera_intel.core.media_forensics.c2pa.read_file")
    def test_content_provenance_check_success(self, mock_c2pa_read):
        """Tests the C2PA provenance check for a valid file."""
        # Arrange
        mock_manifest = MagicMock()
        mock_manifest.get.side_effect = lambda key, default=None: {
            "issuer": "C2PA News Authority",
            "assertions": [{"data": {"action": "created"}}]
        }.get(key, default)

        mock_store = MagicMock()
        mock_store.get_active.return_value = mock_manifest
        mock_c2pa_read.return_value = mock_store

        # Act
        from chimera_intel.core.media_forensics import content_provenance_check
        result = content_provenance_check(pathlib.Path("signed.jpg"))

        # Assert
        self.assertIsInstance(result, ProvenanceResult)
        self.assertTrue(result.has_c2pa_credentials)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.issuer, "C2PA News Authority")
        self.assertEqual(result.manifest_history[0]["action"], "created")

    @patch("chimera_intel.core.media_forensics.c2pa.read_file")
    def test_content_provenance_check_failure(self, mock_c2pa_read):
        """Tests the C2PA provenance check for a file with no manifest."""
        # Arrange
        mock_c2pa_read.return_value = None # No manifest store

        # Act
        from chimera_intel.core.media_forensics import content_provenance_check
        result = content_provenance_check(pathlib.Path("unsigned.jpg"))
        
        # Assert
        self.assertFalse(result.has_c2pa_credentials)
        self.assertIsNone(result.issuer)
        self.assertIn("No C2PA manifest found", result.error)

    @patch("chimera_intel.core.media_forensics.httpx.Client")
    @patch("chimera_intel.core.media_forensics.whois.query")
    @patch("chimera_intel.core.media_forensics.nlp")
    def test_source_poisoning_detect_new_domain(self, mock_nlp, mock_whois, mock_http_client):
        """Tests the source poisoning detection for a new domain."""
        # Arrange
        mock_domain_info = MagicMock()
        mock_domain_info.creation_date = datetime.now() # Created today
        mock_whois.return_value = mock_domain_info
        
        mock_response = MagicMock()
        mock_response.text = "<html><body>This is a normal news story.</body></html>"
        mock_http_client.return_value.__enter__.return_value.get.return_value = mock_response

        # Mock Spacy
        mock_doc = MagicMock()
        mock_doc.__iter__.return_value = [] # No polarizing words
        mock_nlp.return_value = mock_doc

        # Act
        from chimera_intel.core.media_forensics import source_poisoning_detect
        result = source_poisoning_detect("http://new-domain.com")

        # Assert
        self.assertIsInstance(result, PoisoningDetectionResult)
        self.assertFalse(result.is_compromised) # Low confidence
        self.assertIn("Source domain is very new (0 days old)", result.indicators)
        self.assertEqual(len(result.indicators), 1)

    # --- CLI Tests ---
    
    @patch("chimera_intel.core.media_forensics.load_models") # Stop models from loading
    @patch("chimera_intel.core.media_forensics.forensic_artifact_scan")
    def test_cli_artifact_scan(self, mock_scan, mock_load):
        """Tests the 'forensics artifact-scan' CLI command."""
        # Arrange
        mock_scan.return_value = ForensicArtifactResult(
            file_path="test.jpg",
            artifacts_found=["JPEG Ghosting"]
        )
        
        with tempfile.NamedTemporaryFile() as dummy_file:
            with tempfile.NamedTemporaryFile("w+", delete=True, suffix=".json") as tmp_out:
                # Act
                result = runner.invoke(
                    forensics_app, ["artifact-scan", dummy_file.name, "--output", tmp_out.name]
                )
                # Assert
                self.assertEqual(result.exit_code, 0)
                mock_scan.assert_called_with(pathlib.Path(dummy_file.name))
                with open(tmp_out.name, "r") as f:
                    output = json.load(f)
                self.assertEqual(output["file_path"], "test.jpg")
                self.assertIn("JPEG Ghosting", output["artifacts_found"])

    @patch("chimera_intel.core.media_forensics.load_models")
    @patch("chimera_intel.core.media_forensics.newspaper.build")
    @patch("chimera_intel.core.media_forensics.NMF")
    @patch("chimera_intel.core.media_forensics.TfidfVectorizer")
    def test_cli_map_narrative(self, mock_tfidf, mock_nmf, mock_news_build, mock_load):
        """Tests the 'forensics map-narrative' CLI command."""
        # Arrange
        # Mock newspaper article
        mock_article = MagicMock()
        mock_article.source_url = "http://example.com"
        mock_article.text = "This is a test article about elections"
        
        # Mock newspaper.build()
        mock_source = MagicMock()
        mock_source.articles = [mock_article]
        mock_news_build.return_value = mock_source
        
        # Mock sklearn
        mock_tfidf_inst = MagicMock()
        mock_tfidf_inst.get_feature_names_out.return_value = ["elections", "test", "article"]
        mock_tfidf.return_value.fit_transform.return_value = np.array([[1, 1, 1]])
        
        mock_nmf_inst = MagicMock()
        mock_nmf_inst.components_ = [np.array([0.9, 0.8, 0.7])]
        mock_nmf.return_value.fit.return_value = mock_nmf_inst
        mock_nmf.return_value.transform.return_value = np.array([[1.0]])

        with tempfile.NamedTemporaryFile("w+", delete=True, suffix=".json") as tmp_out:
            # Act
            result = runner.invoke(
                forensics_app, ["map-narrative", "Elections", "--output", tmp_out.name]
            )
            
            # Assert
            self.assertEqual(result.exit_code, 0)
            mock_news_build.assert_called_once()
            with open(tmp_out.name, "r") as f:
                output = json.load(f)

            self.assertEqual(output["topic"], "Elections")
            self.assertIn("Narrative 1: elections test article", output["key_narratives"][0])
            self.assertIn("example.com", output["origin_nodes"])


if __name__ == "__main__":
    unittest.main()