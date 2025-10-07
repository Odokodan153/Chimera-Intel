import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner

from chimera_intel.core.industry_intel import (
    get_industry_analysis,
    check_monopoly_status,
    industry_intel_app,
)
from chimera_intel.core.schemas import (
    IndustryIntelResult,
    MonopolyAnalysisResult,
    GNewsResult,
    SWOTAnalysisResult,
)

runner = CliRunner()


class TestIndustryIntel(unittest.IsolatedAsyncioTestCase):
    """Test cases for the Industry Intelligence module."""

    # --- Function Tests ---

    @patch("chimera_intel.core.industry_intel.get_news_gnews", new_callable=AsyncMock)
    @patch("chimera_intel.core.industry_intel.generate_swot_from_data")
    @patch("chimera_intel.core.industry_intel.API_KEYS")
    async def test_get_industry_analysis_success(
        self, mock_api_keys, mock_gen_swot, mock_get_news
    ):
        """Tests a successful industry analysis."""
        # Arrange

        mock_api_keys.gnews_api_key = "fake_gnews_key"
        mock_api_keys.google_api_key = "fake_google_key"
        mock_get_news.return_value = GNewsResult(
            articles=[
                {
                    "title": "Industry News",
                    "description": "...",
                    "url": "",
                    "source": {},
                }
            ]
        )
        mock_gen_swot.return_value = SWOTAnalysisResult(
            analysis_text="## Market Overview"
        )

        # Act

        result = await get_industry_analysis("semiconductors", "Taiwan")

        # Assert

        self.assertIsInstance(result, IndustryIntelResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.industry, "semiconductors")
        self.assertEqual(result.country, "Taiwan")
        self.assertIn("Market Overview", result.analysis_text)
        mock_get_news.assert_awaited_with(
            '"semiconductors" industry in Taiwan', "fake_gnews_key"
        )

    async def test_get_industry_analysis_missing_keys(self):
        """Tests industry analysis when API keys are missing."""
        with patch("chimera_intel.core.industry_intel.API_KEYS.gnews_api_key", None):
            result = await get_industry_analysis("test industry")
            self.assertIsNotNone(result.error)
            self.assertIn("GNews and/or Google API key not found", result.error)

    @patch("chimera_intel.core.industry_intel.get_news_gnews", new_callable=AsyncMock)
    @patch("chimera_intel.core.industry_intel.API_KEYS")
    async def test_check_monopoly_status_no_articles(
        self, mock_api_keys, mock_get_news
    ):
        """Tests monopoly check when no news articles are found."""
        # Arrange

        mock_api_keys.gnews_api_key = "fake_gnews_key"
        mock_api_keys.google_api_key = "fake_google_key"
        mock_get_news.return_value = GNewsResult(articles=[])

        # Act

        result = await check_monopoly_status("MegaCorp", "widgets")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("Could not find any relevant news articles", result.error)

    # --- CLI Tests ---

    @patch(
        "chimera_intel.core.industry_intel.get_industry_analysis",
        new_callable=AsyncMock,
    )
    def test_cli_run_industry_analysis_success(self, mock_get_analysis):
        """Tests the 'industry-intel run' CLI command."""
        # Arrange

        mock_get_analysis.return_value = IndustryIntelResult(
            industry="test", analysis_text="### Analysis"
        )

        # Act

        result = runner.invoke(industry_intel_app, ["run", "test", "--country", "USA"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Industry Analysis: Test in Usa", result.stdout)
        self.assertIn("Analysis", result.stdout)
        mock_get_analysis.assert_awaited_with("test", "USA")

    @patch(
        "chimera_intel.core.industry_intel.check_monopoly_status",
        new_callable=AsyncMock,
    )
    def test_cli_run_monopoly_check_success(self, mock_check_monopoly):
        """Tests the 'industry-intel monopoly' CLI command."""
        # Arrange

        mock_check_monopoly.return_value = MonopolyAnalysisResult(
            company_name="TestCo",
            industry="widgets",
            analysis_text="## Monopoly Assessment",
        )

        # Act

        result = runner.invoke(industry_intel_app, ["monopoly", "TestCo", "widgets"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Monopoly Analysis: Testco in Widgets", result.stdout)
        self.assertIn("Monopoly Assessment", result.stdout)
        mock_check_monopoly.assert_awaited_with("TestCo", "widgets", None)


if __name__ == "__main__":
    unittest.main()
