import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from chimera_intel.core.web_visual_diff import web_visual_diff_app

runner = CliRunner()


class TestWebVisualDiff(unittest.TestCase):
    """Test cases for the Web Visual Diff module."""

    # Patch 'PIL' imports and 'resolve_target'
    @patch("chimera_intel.core.web_visual_diff.ImageEnhance")
    @patch("chimera_intel.core.web_visual_diff.ImageChops")
    @patch("chimera_intel.core.web_visual_diff.Image")
    @patch("chimera_intel.core.web_visual_diff.resolve_target")
    @patch(
        "chimera_intel.core.web_visual_diff.get_last_two_scans_with_screenshots"
    )
    def test_cli_diff_success(
        self,
        mock_get_scans,
        mock_resolve,
        mock_Image,
        mock_ImageChops,
        mock_ImageEnhance,
    ):
        """Tests a successful 'visual-diff run' command."""
        # Arrange
        mock_resolve.return_value = "example.com"
        mock_get_scans.return_value = (
            {"screenshot_path": "/scans/latest.png"},  # latest
            {"screenshot_path": "/scans/previous.png"},  # previous
        )

        # Mock the PIL chain
        mock_img1 = MagicMock()
        mock_img2 = MagicMock()
        mock_img1.size = (800, 600)
        mock_img1.mode = "RGB"
        mock_img2.size = (800, 600)
        mock_img2.mode = "RGB"

        mock_diff_img = MagicMock()
        mock_enhanced_img = MagicMock()
        mock_enhanced_img.getextrema.return_value = ((0, 255), (0, 128), (0, 0))

        mock_Image.open.side_effect = [mock_img1, mock_img2]
        mock_ImageChops.difference.return_value = mock_diff_img
        mock_ImageEnhance.Brightness.return_value.enhance.return_value = (
            mock_enhanced_img
        )

        # Act
        result = runner.invoke(
            web_visual_diff_app, ["run", "-t", "example.com", "-o", "my_diff.png"]
        )

        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        mock_get_scans.assert_called_with("example.com", "page_monitor")
        mock_Image.open.assert_any_call("/scans/previous.png")
        mock_Image.open.assert_any_call("/scans/latest.png")
        mock_ImageChops.difference.assert_called_with(mock_img1, mock_img2)
        mock_enhanced_img.save.assert_called_with("my_diff.png")
        self.assertIn("Visual diff saved to: my_diff.png", result.output)
        self.assertIn("Pixels changed (sum of max channel values): 383", result.output)

    @patch("chimera_intel.core.web_visual_diff.resolve_target")
    @patch(
        "chimera_intel.core.web_visual_diff.get_last_two_scans_with_screenshots"
    )
    def test_cli_diff_no_data(self, mock_get_scans, mock_resolve):
        """Tests CLI failure when no screenshot data is found."""
        # Arrange
        mock_resolve.return_value = "example.com"
        mock_get_scans.return_value = (None, None)

        # Act
        result = runner.invoke(
            web_visual_diff_app, ["run", "-t", "example.com", "-o", "my_diff.png"]
        )

        # Assert
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Not enough historical screenshot data", result.output)