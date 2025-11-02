import unittest
from unittest.mock import patch, AsyncMock
from typer.testing import CliRunner

from chimera_intel.core.industry_intel import (
    get_industry_analysis,
    check_monopoly_status,
    get_stability_forecast,  # Import new function
    track_patent_rd,  # Import new function
    get_market_intelligence,  # Import new function
    monitor_esg_sustainability,  # Import new function
    industry_intel_app,
)
from chimera_intel.core.schemas import (
    IndustryIntelResult,
    MonopolyAnalysisResult,
    StabilityForecastResult,  # Import new schema
    PatentRDResult,  # Import new schema
    MarketIntelResult,  # Import new schema
    ESGMonitorResult,  # Import new schema
    GNewsResult,
    GNewsArticle,  # Import this for creating mock articles
    SWOTAnalysisResult,  # Rename to match source
)

runner = CliRunner()


class TestIndustryIntel(unittest.IsolatedAsyncioTestCase):
    """Test cases for the Industry Intelligence module."""

    # Helper to create mock articles
    def _create_mock_articles(self, count=1):
        articles = []
        for i in range(count):
            articles.append(
                GNewsArticle(
                    title=f"Test Article {i+1}",
                    description="Test description...",
                    url="http://example.com",
                    source={"name": "Test Source"},
                )
            )
        return GNewsResult(articles=articles)

    # Helper to create mock AI result
    def _create_mock_ai_result(self, text="## Analysis"):
        return SWOTAnalysisResult(analysis_text=text, error=None)

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
        mock_get_news.return_value = self._create_mock_articles()
        mock_gen_swot.return_value = self._create_mock_ai_result(
            "## Market Overview"
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

    # +++ NEW FUNCTION TEST +++
    @patch("chimera_intel.core.industry_intel.get_news_gnews", new_callable=AsyncMock)
    @patch("chimera_intel.core.industry_intel.generate_swot_from_data")
    @patch("chimera_intel.core.industry_intel.API_KEYS")
    async def test_track_patent_rd_success(
        self, mock_api_keys, mock_gen_swot, mock_get_news
    ):
        """Tests a successful patent and R&D tracking."""
        # Arrange
        mock_api_keys.gnews_api_key = "fake_gnews_key"
        mock_api_keys.google_api_key = "fake_google_key"
        mock_get_news.return_value = self._create_mock_articles()
        mock_gen_swot.return_value = self._create_mock_ai_result("## Patent Activity")

        # Act
        result = await track_patent_rd("graphene", "Samsung")

        # Assert
        self.assertIsInstance(result, PatentRDResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.topic, "graphene")
        self.assertEqual(result.company, "Samsung")
        self.assertIn("Patent Activity", result.analysis_text)
        mock_get_news.assert_awaited_with(
            '"graphene" patent OR "graphene" R&D OR "graphene" research AND "Samsung"',
            "fake_gnews_key",
        )

    # +++ NEW FUNCTION TEST +++
    @patch("chimera_intel.core.industry_intel.get_news_gnews", new_callable=AsyncMock)
    @patch("chimera_intel.core.industry_intel.generate_swot_from_data")
    @patch("chimera_intel.core.industry_intel.API_KEYS")
    async def test_get_market_intelligence_success(
        self, mock_api_keys, mock_gen_swot, mock_get_news
    ):
        """Tests a successful market intelligence analysis."""
        # Arrange
        mock_api_keys.gnews_api_key = "fake_gnews_key"
        mock_api_keys.google_api_key = "fake_google_key"
        mock_get_news.return_value = self._create_mock_articles()
        mock_gen_swot.return_value = self._create_mock_ai_result("## Pricing Trends")

        # Act
        result = await get_market_intelligence("iPhone 15", "smartphone", "USA")

        # Assert
        self.assertIsInstance(result, MarketIntelResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.product, "iPhone 15")
        self.assertEqual(result.industry, "smartphone")
        self.assertEqual(result.country, "USA")
        self.assertIn("Pricing Trends", result.analysis_text)
        mock_get_news.assert_awaited_with(
            '"iPhone 15" pricing trends in USA OR "smartphone" market competition in USA OR "iPhone 15" reviews',
            "fake_gnews_key",
        )

    # +++ NEW FUNCTION TEST +++
    @patch("chimera_intel.core.industry_intel.get_news_gnews", new_callable=AsyncMock)
    @patch("chimera_intel.core.industry_intel.generate_swot_from_data")
    @patch("chimera_intel.core.industry_intel.API_KEYS")
    async def test_monitor_esg_sustainability_success(
        self, mock_api_keys, mock_gen_swot, mock_get_news
    ):
        """Tests a successful ESG monitoring analysis."""
        # Arrange
        mock_api_keys.gnews_api_key = "fake_gnews_key"
        mock_api_keys.google_api_key = "fake_google_key"
        mock_get_news.return_value = self._create_mock_articles()
        mock_gen_swot.return_value = self._create_mock_ai_result("## Environmental (E)")

        # Act
        result = await monitor_esg_sustainability("Tesla", "automotive")

        # Assert
        self.assertIsInstance(result, ESGMonitorResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.company, "Tesla")
        self.assertEqual(result.industry, "automotive")
        self.assertIn("Environmental (E)", result.analysis_text)
        mock_get_news.assert_awaited_with(
            '"Tesla" ESG OR "Tesla" "environmental social governance" OR "Tesla" sustainability OR "automotive" ESG trends',
            "fake_gnews_key",
        )

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

    @patch(
        "chimera_intel.core.industry_intel.get_stability_forecast",
        new_callable=AsyncMock,
    )
    def test_cli_run_stability_forecast_success(self, mock_get_forecast):
        """Tests the 'industry-intel stability-forecast' CLI command."""
        # Arrange
        mock_get_forecast.return_value = StabilityForecastResult(
            country="Testland",
            analysis_text="## Forecast",
            key_factors={"sources_found": {"political": 1}},
        )

        # Act
        result = runner.invoke(industry_intel_app, ["stability-forecast", "Testland"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Stability Forecast: Testland", result.stdout)
        self.assertIn("Forecast", result.stdout)
        self.assertIn("Key Factors Inspected", result.stdout)
        mock_get_forecast.assert_awaited_with("Testland", None)

    # +++ NEW CLI TEST +++
    @patch(
        "chimera_intel.core.industry_intel.track_patent_rd",
        new_callable=AsyncMock,
    )
    def test_cli_run_patent_rd_success(self, mock_track_rd):
        """Tests the 'industry-intel patent-rd' CLI command."""
        # Arrange
        mock_track_rd.return_value = PatentRDResult(
            topic="AI", company="Google", analysis_text="## R&D"
        )

        # Act
        result = runner.invoke(
            industry_intel_app, ["patent-rd", "AI", "--company", "Google"]
        )

        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Patent & R&D Tracking: Ai (Focus: Google)", result.stdout)
        self.assertIn("R&D", result.stdout)
        mock_track_rd.assert_awaited_with("AI", "Google")

    # +++ NEW CLI TEST +++
    @patch(
        "chimera_intel.core.industry_intel.get_market_intelligence",
        new_callable=AsyncMock,
    )
    def test_cli_run_market_intel_success(self, mock_market_intel):
        """Tests the 'industry-intel market-intel' CLI command."""
        # Arrange
        mock_market_intel.return_value = MarketIntelResult(
            product="TestProduct",
            industry="TestIndustry",
            analysis_text="## Pricing",
        )

        # Act
        result = runner.invoke(
            industry_intel_app, ["market-intel", "TestProduct", "TestIndustry"]
        )

        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn(
            "Market Intelligence: Testproduct in Testindustry", result.stdout
        )
        self.assertIn("Pricing", result.stdout)
        mock_market_intel.assert_awaited_with("TestProduct", "TestIndustry", None)

    # +++ NEW CLI TEST +++
    @patch(
        "chimera_intel.core.industry_intel.monitor_esg_sustainability",
        new_callable=AsyncMock,
    )
    def test_cli_run_esg_monitor_success(self, mock_esg_monitor):
        """Tests the 'industry-intel esg-monitor' CLI command."""
        # Arrange
        mock_esg_monitor.return_value = ESGMonitorResult(
            company="TestCo", analysis_text="## Social (S)"
        )

        # Act
        result = runner.invoke(industry_intel_app, ["esg-monitor", "TestCo"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn("ESG & Sustainability Monitor: Testco", result.stdout)
        self.assertIn("Social (S)", result.stdout)
        mock_esg_monitor.assert_awaited_with("TestCo", None)


if __name__ == "__main__":
    unittest.main()