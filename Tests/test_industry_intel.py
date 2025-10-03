import unittest
from unittest.mock import patch, AsyncMock
from chimera_intel.core.schemas import MonopolyAnalysisResult
from chimera_intel.core.industry_intel import get_industry_analysis,check_monopoly_status
from chimera_intel.core.schemas import (
    IndustryIntelResult,
    GNewsResult,
    NewsArticle,
    SWOTAnalysisResult,
)


class TestIndustryIntel(unittest.IsolatedAsyncioTestCase):
    """Test cases for the industry_intel module."""

    @patch("chimera_intel.core.industry_intel.get_news_gnews", new_callable=AsyncMock)
    @patch("chimera_intel.core.industry_intel.generate_swot_from_data")
    async def test_get_industry_analysis_success(self, mock_ai_generate, mock_get_news):
        """Tests a successful industry analysis run."""
        # Arrange

        mock_get_news.return_value = GNewsResult(
            articles=[
                NewsArticle(
                    title="Water Dispenser Market Booming",
                    description="The global market for water dispensers is expected to grow.",
                    url="http://example.com/news1",
                    source={},
                )
            ]
        )
        mock_ai_generate.return_value = SWOTAnalysisResult(
            analysis_text="## Industry Analysis"
        )

        # Act

        with patch(
            "chimera_intel.core.industry_intel.API_KEYS.gnews_api_key", "fake_key"
        ), patch(
            "chimera_intel.core.industry_intel.API_KEYS.google_api_key", "fake_key"
        ):
            result = await get_industry_analysis("water dispenser", country="USA")
        # Assert

        self.assertIsInstance(result, IndustryIntelResult)
        self.assertIsNone(result.error)
        self.assertIn("Industry Analysis", result.analysis_text)
        mock_get_news.assert_awaited_once_with(
            '"water dispenser" industry in USA', "fake_key"
        )
        mock_ai_generate.assert_called_once()

    async def test_get_industry_analysis_no_api_keys(self):
        """Tests that the function returns an error if API keys are missing."""
        with patch("chimera_intel.core.industry_intel.API_KEYS.gnews_api_key", None):
            result = await get_industry_analysis("test industry")
            self.assertIsNotNone(result.error)
            self.assertIn("GNews and/or Google API key not found", result.error)

    @patch("chimera_intel.core.industry_intel.get_news_gnews", new_callable=AsyncMock)
    @patch("chimera_intel.core.industry_intel.generate_swot_from_data")
    async def test_check_monopoly_status_success(self, mock_ai_generate, mock_get_news):
        """Tests a successful monopoly analysis."""
        # Arrange
        mock_get_news.return_value = GNewsResult(
            articles=[
                NewsArticle(
                    title="NewCo Dominates Market with 80% Share",
                    description="Competitor OldCo struggles to keep up.",
                    url="http://example.com/news1",
                    source={},
                )
            ]
        )
        mock_ai_generate.return_value = SWOTAnalysisResult(analysis_text="## Monopoly Assessment")

        # Act
        with patch("chimera_intel.core.industry_intel.API_KEYS.gnews_api_key", "fake_key"), \
             patch("chimera_intel.core.industry_intel.API_KEYS.google_api_key", "fake_key"):
            result = await check_monopoly_status("NewCo", "widgets")

        # Assert
        self.assertIsInstance(result, MonopolyAnalysisResult)
        self.assertIsNone(result.error)
        self.assertIn("Monopoly Assessment", result.analysis_text)
        mock_ai_generate.assert_called_once()
        
if __name__ == "__main__":
    unittest.main()
