import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner
import json

from chimera_intel.core.ecosystem_intel import (
    find_partners,
    find_competitors,
    find_distributors,
    ecosystem_app,
)
from chimera_intel.core.schemas import (
    EcosystemResult,
    DiscoveredPartner,
    DiscoveredCompetitor,
    DiscoveredDistributor,
    GNewsResult,
    TradeDataResult,
    ProjectConfig,
)

runner = CliRunner()


class TestEcosystemIntel(unittest.IsolatedAsyncioTestCase):
    """Test cases for the Ecosystem Intelligence module."""

    # --- Partner Discovery Tests ---

    @patch("chimera_intel.core.ecosystem_intel.get_news_gnews", new_callable=AsyncMock)
    @patch(
        "chimera_intel.core.ecosystem_intel.get_tech_stack_wappalyzer",
        new_callable=AsyncMock,
    )
    @patch("chimera_intel.core.ecosystem_intel.API_KEYS")
    async def test_find_partners_success(
        self, mock_api_keys, mock_wappalyzer, mock_gnews
    ):
        """Tests successful partner discovery from multiple sources."""
        # Arrange

        mock_api_keys.gnews_api_key = "fake_gnews_key"
        mock_api_keys.wappalyzer_api_key = "fake_wappalyzer_key"
        mock_gnews.return_value = GNewsResult(
            articles=[
                {
                    "title": "MegaCorp Announces Partnership with Partner Inc.",
                    "description": "",
                    "url": "",
                    "source": {},
                }
            ]
        )
        mock_wappalyzer.return_value = ["Salesforce", "SomeOtherTech"]

        # Act

        partners = await find_partners("MegaCorp", "megacorp.com")

        # Assert

        self.assertEqual(len(partners), 2)
        partner_names = {p.partner_name for p in partners}
        self.assertIn("Partner Inc.", partner_names)
        self.assertIn("Salesforce", partner_names)

    # --- Competitor Discovery Tests ---

    @patch(
        "chimera_intel.core.ecosystem_intel.async_client.get", new_callable=AsyncMock
    )
    @patch("chimera_intel.core.ecosystem_intel.API_KEYS")
    async def test_find_competitors_success(self, mock_api_keys, mock_get):
        """Tests successful competitor discovery using SimilarWeb."""
        # Arrange

        mock_api_keys.similarweb_api_key = "fake_sw_key"
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "similar_sites": [{"site": "competitor.com", "score": 0.9}]
        }
        mock_get.return_value = mock_response

        # Act

        competitors = await find_competitors("example.com")

        # Assert

        self.assertEqual(len(competitors), 1)
        self.assertEqual(competitors[0].competitor_name, "competitor.com")
        self.assertEqual(competitors[0].confidence, "High")

    async def test_find_competitors_no_api_key(self):
        """Tests competitor discovery when the SimilarWeb API key is missing."""
        with patch(
            "chimera_intel.core.ecosystem_intel.API_KEYS.similarweb_api_key", None
        ):
            competitors = await find_competitors("example.com")
            # Should return an empty list gracefully

            self.assertEqual(len(competitors), 0)

    # --- Distributor Discovery Tests ---

    @patch("chimera_intel.core.ecosystem_intel.get_trade_data")
    async def test_find_distributors_success(self, mock_get_trade_data):
        """Tests successful distributor discovery from trade data."""
        # Arrange

        mock_get_trade_data.return_value = TradeDataResult(
            shipments=[
                {"consignee": "Distributor A"},
                {"consignee": "Distributor A"},
                {"consignee": "Distributor B"},
            ],
            total_shipments=3,
        )

        # Act

        distributors = await find_distributors("TestCorp")

        # Assert

        self.assertEqual(len(distributors), 2)
        distributor_names = {d.distributor_name for d in distributors}
        self.assertIn("Distributor A", distributor_names)
        self.assertIn("Distributor B", distributor_names)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.ecosystem_intel.find_partners", new_callable=AsyncMock)
    @patch(
        "chimera_intel.core.ecosystem_intel.find_competitors", new_callable=AsyncMock
    )
    @patch(
        "chimera_intel.core.ecosystem_intel.find_distributors", new_callable=AsyncMock
    )
    def test_cli_run_success_with_args(
        self, mock_distributors, mock_competitors, mock_partners
    ):
        """Tests a successful run of the 'ecosystem run' command with direct arguments."""
        # Arrange

        mock_partners.return_value = [
            DiscoveredPartner(
                partner_name="PartnerCo", source="", details="", confidence=""
            )
        ]
        mock_competitors.return_value = []
        mock_distributors.return_value = []

        # Act

        result = runner.invoke(ecosystem_app, ["run", "MyCompany", "mycompany.com"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["target_company"], "MyCompany")
        self.assertEqual(len(output["ecosystem_data"]["partners"]), 1)
        mock_partners.assert_awaited_with("MyCompany", "mycompany.com")

    @patch("chimera_intel.core.ecosystem_intel.get_active_project")
    @patch("chimera_intel.core.ecosystem_intel.find_partners", new_callable=AsyncMock)
    @patch(
        "chimera_intel.core.ecosystem_intel.find_competitors", new_callable=AsyncMock
    )
    @patch(
        "chimera_intel.core.ecosystem_intel.find_distributors", new_callable=AsyncMock
    )
    def test_cli_run_with_project(
        self, mock_distributors, mock_competitors, mock_partners, mock_get_project
    ):
        """NEW: Tests the CLI command using an active project's context."""
        # Arrange

        mock_project = ProjectConfig(
            project_name="Test",
            created_at="",
            company_name="ProjectCorp",
            domain="project.com",
        )
        mock_get_project.return_value = mock_project
        mock_partners.return_value = []
        mock_competitors.return_value = []
        mock_distributors.return_value = []

        # Act

        result = runner.invoke(ecosystem_app, ["run"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Using targets from active project", result.stdout)
        mock_partners.assert_awaited_with("ProjectCorp", "project.com")

    @patch("chimera_intel.core.ecosystem_intel.get_active_project", return_value=None)
    def test_cli_run_no_target_or_project(self, mock_get_project):
        """NEW: Tests CLI failure when no target is given and no project is active."""
        # Act

        result = runner.invoke(ecosystem_app, ["run"])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Company name and domain must be provided", result.stdout)


if __name__ == "__main__":
    unittest.main()
