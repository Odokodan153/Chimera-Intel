import unittest
import pathlib
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
import numpy as np
from PIL import Image
# Module to test
from chimera_intel.core.media_forensics import (
    forensics_app,
    forensic_artifact_scan,
    content_provenance_check
)

runner = CliRunner()


class TestMediaForensics(unittest.TestCase):
    """
    Test cases for the Deepfake & Photoshop Forensics module.
    (Existing tests from your file)
    """

    @patch("chimera_intel.core.media_forensics.Image.open")
    def test_forensic_artifact_scan_ela(self, mock_image_open):
        """Tests ELA artifact detection."""
        # Arrange
        mock_img = MagicMock(spec=Image.Image)
        mock_img.getexif.return_value = {}
        
        # Mock ImageChops.difference to return a non-zero diff
        with patch("chimera_intel.core.media_forensics.ImageChops.difference") as mock_diff:
            mock_ela_img = MagicMock()
            mock_ela_img.getextrema.return_value = [(0, 100)]
            mock_ela_img.convert.return_value.std.return_value = 25 # > 20 threshold
            
            mock_diff.return_value = mock_ela_img
            
            # Mock ImageEnhance to return the mock
            with patch("chimera_intel.core.media_forensics.ImageEnhance.Brightness") as mock_enhance:
                mock_enhance.return_value.enhance.return_value = mock_ela_img
                
                mock_image_open.return_value.__enter__.return_value = mock_img
                
                # Act
                result = forensic_artifact_scan(pathlib.Path("test.jpg"))

                # Assert
                self.assertIn("High Variance Error Level Analysis (ELA)", result.artifacts_found)

    @patch("chimera_intel.core.media_forensics.c2pa.read_file")
    def test_content_provenance_check_success(self, mock_read_file):
        """Tests successful C2PA data extraction."""
        # Arrange
        mock_manifest = MagicMock()
        mock_manifest.get.side_effect = lambda key, default=None: {
            "issuer": "TestIssuer",
            "assertions": [{"data": {"action": "created"}}]
        }.get(key, default)
        
        mock_store = MagicMock()
        mock_store.get_active.return_value = mock_manifest
        mock_read_file.return_value = mock_store

        # Act
        result = content_provenance_check(pathlib.Path("test.jpg"))

        # Assert
        self.assertTrue(result.has_c2pa_credentials)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.issuer, "TestIssuer")
        self.assertEqual(len(result.manifest_history), 1)
        self.assertEqual(result.manifest_history[0]["action"], "created")


# --- [NEW] Test Class for Face Recognition ---

class TestFaceRecognition(unittest.TestCase):
    
    def setUp(self):
        self.runner = CliRunner()
        # Mock encodings
        self.mock_encoding_a = np.array([0.1] * 128)
        self.mock_encoding_b = np.array([0.2] * 128)

    @patch("chimera_intel.core.media_forensics.face_recognition")
    def test_cli_face_recognize_find(self, mock_face_rec):
        """Tests the 'face-recognize --mode find' CLI command."""
        # Arrange
        mock_face_rec.load_image_file.return_value = MagicMock()
        mock_face_rec.face_locations.return_value = [(10, 60, 50, 20)] # (top, right, bottom, left)

        with runner.isolated_filesystem():
            with open("test.jpg", "w") as f: f.write("dummy")
            
            # Act
            result = self.runner.invoke(
                forensics_app, ["face-recognize", "test.jpg", "--mode", "find"]
            )
            
            # Assert
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Found 1 face(s)", result.stdout)
            self.assertIn("(10, 60, 50, 20)", result.stdout)
            mock_face_rec.face_locations.assert_called_with(unittest.mock.ANY, model="hog")

    @patch("chimera_intel.core.media_forensics.face_recognition")
    def test_cli_face_recognize_encode(self, mock_face_rec):
        """Tests the 'face-recognize --mode encode' CLI command."""
        # Arrange
        mock_face_rec.load_image_file.return_value = MagicMock()
        mock_face_rec.face_locations.return_value = [(10, 60, 50, 20)]
        mock_face_rec.face_encodings.return_value = [self.mock_encoding_a]

        with runner.isolated_filesystem():
            with open("test.jpg", "w") as f: f.write("dummy")
            
            # Act
            result = self.runner.invoke(
                forensics_app, ["face-recognize", "test.jpg", "--mode", "encode"]
            )
            
            # Assert
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Generated 1 encoding(s)", result.stdout)
            self.assertIn("0.1", result.stdout) # Check if encoding is printed

    @patch("chimera_intel.core.media_forensics.face_recognition")
    def test_cli_face_recognize_compare_match(self, mock_face_rec):
        """Tests the 'face-recognize --mode compare' (Match) CLI command."""
        # Arrange
        mock_face_rec.load_image_file.side_effect = [MagicMock(), MagicMock()] # 1st for known, 2nd for unknown
        mock_face_rec.face_encodings.side_effect = [
            [self.mock_encoding_a], # Encodings for known image
            [self.mock_encoding_a]  # Encodings for unknown image
        ]
        mock_face_rec.face_locations.return_value = [(10, 60, 50, 20)] # Locations for unknown
        mock_face_rec.compare_faces.return_value = [True]
        mock_face_rec.face_distance.return_value = [0.1234]

        with runner.isolated_filesystem():
            with open("known.jpg", "w") as f: f.write("dummy")
            with open("unknown.jpg", "w") as f: f.write("dummy")
            
            # Act
            result = self.runner.invoke(
                forensics_app, 
                ["face-recognize", "known.jpg", "--mode", "compare", "--compare", "unknown.jpg"]
            )
            
            # Assert
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Yes", result.stdout)
            self.assertIn("0.1234", result.stdout)

    @patch("chimera_intel.core.media_forensics.face_recognition")
    def test_cli_face_recognize_compare_no_match(self, mock_face_rec):
        """Tests the 'face-recognize --mode compare' (No Match) CLI command."""
        # Arrange
        mock_face_rec.load_image_file.side_effect = [MagicMock(), MagicMock()]
        mock_face_rec.face_encodings.side_effect = [
            [self.mock_encoding_a], # Known
            [self.mock_encoding_b]  # Unknown
        ]
        mock_face_rec.face_locations.return_value = [(10, 60, 50, 20)]
        mock_face_rec.compare_faces.return_value = [False]
        mock_face_rec.face_distance.return_value = [0.9876]

        with runner.isolated_filesystem():
            with open("known.jpg", "w") as f: f.write("dummy")
            with open("unknown.jpg", "w") as f: f.write("dummy")
            
            # Act
            result = self.runner.invoke(
                forensics_app, 
                ["face-recognize", "known.jpg", "--mode", "compare", "--compare", "unknown.jpg"]
            )
            
            # Assert
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No", result.stdout)
            self.assertIn("0.9876", result.stdout)


if __name__ == "__main__":
    unittest.main()