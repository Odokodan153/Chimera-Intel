import unittest
import asyncio  # <-- FIX 1: Import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner

from chimera_intel.core.ecosystem_intel import (
    find_partners,
    find_competitors,
    find_distributors,
    ecosystem_app,
)
from chimera_intel.core.schemas import (
    GNewsResult,
    TradeDataResult,
    ProjectConfig,
    Shipment,
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
        self.assertIn("Partner Inc", partner_names)
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
                Shipment(
                    date="2023-01-01",
                    consignee="Distributor A",
                    shipper="TestCorp",
                    product_description="Test Product",
                ),
                Shipment(
                    date="2023-01-02",
                    consignee="Distributor A",
                    shipper="TestCorp",
                    product_description="Test Product",
                ),
                Shipment(
                    date="2023-01-03",
                    consignee="Distributor B",
                    shipper="TestCorp",
                    product_description="Test Product",
                ),
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

    @patch(
        "chimera_intel.core.ecosystem_intel.async_run_full_ecosystem_analysis",
        new_callable=AsyncMock,
    )
    def test_cli_run_success_with_args(self, mock_async_run):
        """Tests a successful run of the 'ecosystem run' command with direct arguments."""
        
        # --- FIX 2: Arrange mock to return an awaitable Future ---
        mock_return_future = asyncio.Future()
        mock_return_future.set_result(None)  # Set return value for the async function
        mock_async_run.return_value = mock_return_future
        # --- End Fix 2 ---

        # Act

        result = runner.invoke(ecosystem_app, ["run", "MyCompany", "mycompany.com"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_async_run.assert_awaited_with("MyCompany", "mycompany.com", None)

    @patch("chimera_intel.core.ecosystem_intel.get_active_project")
    @patch(
        "chimera_intel.core.ecosystem_intel.async_run_full_ecosystem_analysis",
        new_callable=AsyncMock,
    )
    def test_cli_run_with_project(self, mock_async_run, mock_get_project):
        """NEW: Tests the CLI command using an active project's context."""
        # Arrange

        # --- ALSO FIX THIS TEST: It has the same AsyncMock issue ---
        mock_return_future = asyncio.Future()
        mock_return_future.set_result(None)
        mock_async_run.return_value = mock_return_future
        # --- End Fix ---

        mock_project = ProjectConfig(
            project_name="Test",
            created_at="",
            company_name="ProjectCorp",
            domain="project.com",
        )
        mock_get_project.return_value = mock_project

        # Act

        result = runner.invoke(ecosystem_app, ["run"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        # --- Revert previous incorrect fix ---
        # The correct call should not have "run" as an argument
        mock_async_run.assert_awaited_with(None, None, None)

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