import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner

# Import the specific Typer app for this module, not the main one


from chimera_intel.core.ecosystem_intel import ecosystem_app
from chimera_intel.core.ecosystem_intel import (
    find_partners,
    find_competitors,
    find_distributors,
)
from chimera_intel.core.schemas import (
    GNewsResult,
    TradeDataResult,
    Shipment,
    ProjectConfig,
    NewsArticle,
)

runner = CliRunner(mix_stderr=False)


class TestEcosystemIntel(unittest.IsolatedAsyncioTestCase):
    """Test cases for the Ecosystem Intelligence module."""

    @patch("chimera_intel.core.ecosystem_intel.API_KEYS")
    @patch("chimera_intel.core.ecosystem_intel.get_news_gnews", new_callable=AsyncMock)
    @patch(
        "chimera_intel.core.ecosystem_intel.get_tech_stack_wappalyzer",
        new_callable=AsyncMock,
    )
    async def test_find_partners(self, mock_get_tech, mock_get_news, mock_api_keys):
        """Tests the partner discovery function."""
        # Arrange

        mock_api_keys.gnews_api_key = "fake_gnews_key"
        mock_api_keys.wappalyzer_api_key = "fake_wapp_key"

        # Corrected mock to ensure "PartnerInc" is found

        mock_get_news.return_value = GNewsResult(
            articles=[
                NewsArticle(
                    title="TestCorp partners with PartnerInc",
                    description="",
                    url="",
                    source={},
                )
            ]
        )
        mock_get_tech.return_value = ["Salesforce CRM"]

        # Act

        partners = await find_partners("TestCorp", "testcorp.com")

        # Assert
        # The test should now find two partners: "PartnerInc" and "Salesforce"

        self.assertEqual(len(partners), 2)
        partner_names = {p.partner_name for p in partners}
        self.assertIn("PartnerInc", partner_names)
        self.assertIn("Salesforce", partner_names)

    @patch(
        "chimera_intel.core.ecosystem_intel.async_client.get", new_callable=AsyncMock
    )
    async def test_find_competitors(self, mock_async_get):
        """Tests the competitor discovery function."""
        # Arrange

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "similar_sites": [{"site": "competitor.com", "score": 0.8}]
        }
        mock_async_get.return_value = mock_response

        # Act

        with patch(
            "chimera_intel.core.ecosystem_intel.API_KEYS.similarweb_api_key", "fake_key"
        ):
            competitors = await find_competitors("example.com")
        # Assert

        self.assertEqual(len(competitors), 1)
        self.assertEqual(competitors[0].competitor_name, "competitor.com")

    @patch("chimera_intel.core.ecosystem_intel.asyncio.to_thread")
    async def test_find_distributors(self, mock_to_thread: AsyncMock):
        """Tests the distributor discovery function."""
        # Arrange

        mock_to_thread.return_value = TradeDataResult(
            total_shipments=1,
            shipments=[
                Shipment(
                    date="2025-01-01",
                    shipper="Factory",
                    consignee="Distributor Inc",
                    product_description="Widgets",
                )
            ],
        )

        # Act

        distributors = await find_distributors("TestCorp")

        # Assert

        self.assertEqual(len(distributors), 1)
        self.assertEqual(distributors[0].distributor_name, "Distributor Inc")

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.ecosystem_intel.find_partners", new_callable=AsyncMock)
    @patch(
        "chimera_intel.core.ecosystem_intel.find_competitors", new_callable=AsyncMock
    )
    @patch(
        "chimera_intel.core.ecosystem_intel.find_distributors", new_callable=AsyncMock
    )
    @patch("chimera_intel.core.ecosystem_intel.save_scan_to_db")
    def test_cli_ecosystem_run_with_args(
        self, mock_save_db, mock_distributors, mock_competitors, mock_partners
    ):
        """Tests the CLI command with explicit arguments."""
        # Arrange

        mock_partners.return_value = []
        mock_competitors.return_value = []
        mock_distributors.return_value = []

        # Act

        result = runner.invoke(
            ecosystem_app, ["TestCorp", "testcorp.com", "--output", "test.json"]
        )

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_partners.assert_awaited_with("TestCorp", "testcorp.com")
        mock_distributors.assert_awaited_with("TestCorp")
        mock_competitors.assert_awaited_with("testcorp.com")
        mock_save_db.assert_called_once()

    @patch("chimera_intel.core.ecosystem_intel.get_active_project")
    @patch("chimera_intel.core.ecosystem_intel.find_partners", new_callable=AsyncMock)
    @patch(
        "chimera_intel.core.ecosystem_intel.find_competitors", new_callable=AsyncMock
    )
    @patch(
        "chimera_intel.core.ecosystem_intel.find_distributors", new_callable=AsyncMock
    )
    @patch("chimera_intel.core.ecosystem_intel.save_scan_to_db")
    def test_cli_ecosystem_run_with_project(
        self,
        mock_save_db,
        mock_distributors,
        mock_competitors,
        mock_partners,
        mock_get_project,
    ):
        """Tests the CLI command using an active project."""
        # Arrange

        mock_project = ProjectConfig(
            project_name="EcosystemTest",
            created_at="2025-01-01",
            company_name="ProjectCorp",
            domain="project.com",
        )
        mock_get_project.return_value = mock_project
        mock_partners.return_value = []
        mock_competitors.return_value = []
        mock_distributors.return_value = []

        # Act

        result = runner.invoke(ecosystem_app, ["--output", "test.json"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Using targets from active project", result.stdout)
        mock_partners.assert_awaited_with("ProjectCorp", "project.com")
        mock_save_db.assert_called_once()

    @patch("chimera_intel.core.ecosystem_intel.get_active_project")
    def test_cli_ecosystem_run_no_args_no_project(self, mock_get_project):
        """Tests CLI failure when no arguments are given and no project is active."""
        # Arrange

        mock_get_project.return_value = None

        # Act

        result = runner.invoke(ecosystem_app, [])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Company name and domain must be provided", result.stdout)


if __name__ == "__main__":
    unittest.main()
