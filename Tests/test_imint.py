import unittest
from unittest.mock import patch, MagicMock

from chimera_intel.core.imint import analyze_image_metadata
from chimera_intel.core.schemas import ImageAnalysisResult


class TestImint(unittest.TestCase):
    """Test cases for the Image & Video Intelligence (IMINT) module."""

    @patch("chimera_intel.core.imint.Image.open")
    def test_analyze_image_metadata_success(self, mock_image_open):
        """Tests successful extraction of EXIF data from an image."""
        # Arrange

        mock_image = MagicMock()
        # Pillow uses integer tags; 271 for 'Make', 272 for 'Model'

        mock_image._getexif.return_value = {271: "Canon", 272: "Canon EOS R5"}
        mock_image_open.return_value.__enter__.return_value = mock_image

        # Act

        result = analyze_image_metadata("test.jpg")

        # Assert

        self.assertIsInstance(result, ImageAnalysisResult)
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.exif_data)
        self.assertEqual(result.exif_data.Make, "Canon")
        self.assertEqual(result.exif_data.Model, "Canon EOS R5")

    @patch("chimera_intel.core.imint.Image.open")
    def test_analyze_image_metadata_no_exif(self, mock_image_open):
        """Tests the case where an image has no EXIF metadata."""
        # Arrange

        mock_image = MagicMock()
        mock_image._getexif.return_value = None  # Simulate no EXIF data
        mock_image_open.return_value.__enter__.return_value = mock_image

        # Act

        result = analyze_image_metadata("no_exif.png")

        # Assert

        self.assertIsNone(result.error)
        self.assertIsNone(result.exif_data)
        self.assertEqual(result.message, "No EXIF metadata found.")

    @patch("chimera_intel.core.imint.Image.open")
    def test_analyze_image_metadata_file_error(self, mock_image_open):
        """Tests error handling when the image file cannot be opened."""
        # Arrange

        mock_image_open.side_effect = FileNotFoundError("File does not exist")

        # Act

        result = analyze_image_metadata("nonexistent.jpg")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("Could not process image", result.error)


if __name__ == "__main__":
    unittest.main()
