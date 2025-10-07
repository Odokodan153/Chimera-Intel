import unittest
import json
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from PIL import Image

from chimera_intel.core.imint import (
    analyze_image_metadata,
    analyze_image_content,
    perform_object_detection,
    imint_app,
)
from chimera_intel.core.schemas import ImageAnalysisResult, ExifData

runner = CliRunner()


class TestImint(unittest.TestCase):
    """Test cases for the Image & Visual Intelligence (IMINT) module."""

    # --- Metadata Analysis Tests ---

    @patch("chimera_intel.core.imint.Image.open")
    def test_analyze_image_metadata_success(self, mock_image_open):
        """Tests successful extraction of EXIF metadata from an image."""
        # Arrange

        mock_image = MagicMock()
        # The _getexif() method returns a dictionary of tag IDs to values

        mock_image._getexif.return_value = {
            271: "Canon",  # Make
            272: "Canon EOS R5",  # Model
        }
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
        """Tests the function's behavior with an image that has no EXIF data."""
        # Arrange

        mock_image = MagicMock()
        mock_image._getexif.return_value = None  # No EXIF data
        mock_image_open.return_value.__enter__.return_value = mock_image

        # Act

        result = analyze_image_metadata("test.jpg")

        # Assert

        self.assertIsNone(result.error)
        self.assertIn("No EXIF metadata found", result.message)

    # --- AI Content Analysis Tests ---

    @patch("chimera_intel.core.imint.genai")
    @patch("chimera_intel.core.imint.Image.open")
    @patch("chimera_intel.core.imint.API_KEYS")
    def test_analyze_image_content_success(
        self, mock_api_keys, mock_image_open, mock_genai
    ):
        """Tests successful AI-powered content analysis."""
        # Arrange

        mock_api_keys.google_api_key = "fake_google_key"
        mock_model_instance = mock_genai.GenerativeModel.return_value
        mock_model_instance.generate_content.return_value.text = "Extracted Text"

        # Act

        result = analyze_image_content("test.jpg", "Extract text.")

        # Assert

        self.assertEqual(result, "Extracted Text")
        mock_genai.configure.assert_called_with(api_key="fake_google_key")
        mock_model_instance.generate_content.assert_called_once()

    # --- Satellite Imagery (Object Detection) Tests ---

    @patch("chimera_intel.core.imint.torch.no_grad")
    @patch("chimera_intel.core.imint.detection_model")
    @patch("chimera_intel.core.imint.Image.open")
    def test_perform_object_detection_success(
        self, mock_image_open, mock_model, mock_no_grad
    ):
        """Tests successful object detection on a satellite image."""
        # Arrange
        # Mock the model's output to simulate detecting a car and a truck

        mock_model.return_value = [
            {"labels": MagicMock(numpy=lambda: [3, 8])}  # 3=car, 8=truck
        ]

        # Act

        result = perform_object_detection("satellite_image.jpg")

        # Assert

        self.assertIn("car", result)
        self.assertIn("truck", result)
        self.assertEqual(result["car"], 1)
        self.assertEqual(result["truck"], 1)

    # --- CLI Tests ---

    @patch("chimera_intel.core.imint.analyze_image_metadata")
    def test_cli_metadata_success(self, mock_analyze_metadata):
        """Tests the 'imint metadata' CLI command."""
        # Arrange

        mock_analyze_metadata.return_value = ImageAnalysisResult(
            file_path="test.jpg", exif_data=ExifData(Make="TestCo")
        )

        # Act

        result = runner.invoke(imint_app, ["metadata", "test.jpg"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["file_path"], "test.jpg")
        self.assertEqual(output["exif_data"]["Make"], "TestCo")

    @patch("chimera_intel.core.imint.analyze_image_content")
    def test_cli_analyze_content_success(self, mock_analyze_content):
        """Tests the 'imint analyze-content' CLI command."""
        # Arrange

        mock_analyze_content.return_value = "AI analysis result text."

        # Act

        result = runner.invoke(
            imint_app, ["analyze-content", "test.jpg", "--feature", "ocr"]
        )

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("AI analysis result text", result.stdout)
        mock_analyze_content.assert_called_once()

    @patch("chimera_intel.core.imint.perform_object_detection")
    @patch("os.path.exists", return_value=True)
    def test_cli_analyze_satellite_success(self, mock_exists, mock_perform_detection):
        """Tests the 'imint analyze-satellite' CLI command."""
        # Arrange

        mock_perform_detection.return_value = {"airplane": 1, "boat": 2}

        # Act

        result = runner.invoke(
            imint_app,
            [
                "analyze-satellite",
                "--coords",
                "0,0",
                "--feature",
                "object-detection",
                "--image",
                "satellite.jpg",
            ],
        )

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Detected 1 instance(s) of 'airplane'", result.stdout)
        self.assertIn("Detected 2 instance(s) of 'boat'", result.stdout)


if __name__ == "__main__":
    unittest.main()
