import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
import typer
import pytest
from datetime import datetime
from chimera_intel.core.finint import (
    get_insider_transactions,
    finint_app,
    analyze_crowdfunding
)
from chimera_intel.core.schemas import (
    InsiderTradingResult,
    InsiderTransaction,
    CrowdfundingAnalysisResult,
    CrowdfundingProject,
    FinancialTransaction, 
    AmlPattern,
    AmlAnalysisResult
)

runner = CliRunner()


class TestFinint(unittest.TestCase):
    """Test cases for the Financial Intelligence (FININT) module."""

    @patch("chimera_intel.core.finint.sync_client.get")
    @patch("chimera_intel.core.finint.API_KEYS")
    def test_track_insider_trading_success(self, mock_api_keys, mock_get):
        """Tests a successful insider trading lookup."""
        # Arrange

        mock_api_keys.finnhub_api_key = "fake_finnhub_key"
        mock_response = unittest.mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "companyName": "Apple Inc.",
                    "insiderName": "John Doe",
                    "transactionShares": 100,
                    "change": 100,
                    "transactionDate": "2023-10-26",
                    "price": 100.0,
                    "transactionCode": "P-Purchase",
                    "transactionType": "Buy",
                }
            ]
        }
        mock_get.return_value = mock_response

        # Act

        result = get_insider_transactions("AAPL")

        # Assert

        self.assertIsInstance(result, InsiderTradingResult)
        self.assertEqual(len(result.transactions), 1)
        self.assertEqual(result.transactions[0].insiderName, "John Doe")
        self.assertIsNone(result.error)

    def test_track_insider_trading_no_api_key(self):
        """Tests insider trading tracking when the Finnhub API key is missing."""
        with patch("chimera_intel.core.finint.API_KEYS.finnhub_api_key", None):
            result = get_insider_transactions("AAPL")
            self.assertIsNotNone(result.error)
            self.assertIn("Finnhub API key not found", result.error)

    @patch("chimera_intel.core.finint.sync_client.get")
    @patch("chimera_intel.core.finint.API_KEYS")
    def test_track_insider_trading_api_error(self, mock_api_keys, mock_get):
        """Tests the function's error handling when the Finnhub API fails."""
        # Arrange

        mock_api_keys.finnhub_api_key = "fake_finnhub_key"
        mock_get.side_effect = Exception("Invalid API Key")

        # Act

        result = get_insider_transactions("AAPL")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("An API error occurred", result.error)
        self.assertIn("Invalid API Key", result.error)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.finint.get_insider_transactions")
    def test_cli_insider_tracking_with_argument(self, mock_get_insider):
        """Tests the 'track-insiders' command with a direct ticker argument."""
        # Arrange

        mock_get_insider.return_value = InsiderTradingResult(
            stock_symbol="MSFT", transactions=[]
        )

        # Act
        # FIX: Removed "track-insiders" from the list

        result = runner.invoke(finint_app, ["--stock-symbol", "MSFT"])

        # Assert

        self.assertEqual(result.exit_code, 0, msg=result.output)
        mock_get_insider.assert_called_with("MSFT")
        self.assertIn("No insider trading data found for this symbol.", result.stdout)

    @patch("chimera_intel.core.finint.resolve_target")
    @patch("chimera_intel.core.finint.get_insider_transactions")
    def test_cli_insider_tracking_with_project(
        self, mock_get_insider, mock_resolve_target
    ):
        """Tests the 'track-insiders' command using an active project's ticker."""
        # Arrange

        mock_resolve_target.return_value = "GOOGL"
        mock_get_insider.return_value = InsiderTradingResult(
            stock_symbol="GOOGL",
            transactions=[
                InsiderTransaction(
                    companyName="Alphabet Inc.",
                    insiderName="Sundar Pichai",
                    transactionShares=1000,
                    change=1000,
                    transactionDate="2023-01-01",
                    price=200.0,
                    transactionCode="S-Sale",
                    transactionType="Sale",
                )
            ],
        )

        # Act
        # FIX: Removed "track-insiders" from the list

        result = runner.invoke(finint_app, [])

        # Assert

        self.assertEqual(result.exit_code, 0, msg=result.output)
        mock_resolve_target.assert_called_with(None, required_assets=["stock_symbol"])
        mock_get_insider.assert_called_with("GOOGL")
        self.assertIn("Sundar Pichai", result.stdout)

    @patch("chimera_intel.core.finint.resolve_target")
    def test_cli_insider_tracking_no_ticker(self, mock_resolve_target):
        """Tests CLI failure when no ticker is provided and no project is active."""
        # Arrange

        mock_resolve_target.side_effect = typer.Exit(code=1)

        # Act
        # FIX: Removed "track-insiders" from the list

        result = runner.invoke(finint_app, [])

        # Assert

        self.assertEqual(result.exit_code, 1)

    @patch("chimera_intel.core.finint.sync_client.get")
    @patch("chimera_intel.core.finint.API_KEYS")
    def test_analyze_crowdfunding_real_api(self, mock_api_keys, mock_get):
        """Tests the crowdfunding analysis by mocking the real API call."""
        # Arrange
        mock_api_keys.kickstarter_api_key = "fake_rapidapi_key"
        
        # This is the mock JSON response from the RapidAPI endpoint
        mock_api_response = {
            "projects": [
                {
                    "id": 123,
                    "name": "Test Gadget Pro",
                    "url": "https://www.kickstarter.com/projects/test/test-gadget-pro",
                    "creator": { "name": "Test Creator" },
                    "goal": 50000.0,
                    "pledged": 75000.0,
                    "backers_count": 800,
                    "state": "successful"
                }
            ]
        }
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_api_response
        mock_get.return_value = mock_response

        # Act
        result = analyze_crowdfunding("Test Gadget")

        # Assert
        self.assertIsInstance(result, CrowdfundingAnalysisResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.projects), 1)
        self.assertEqual(result.projects[0].platform, "Kickstarter")
        self.assertEqual(result.projects[0].project_name, "Test Gadget Pro")
        self.assertEqual(result.projects[0].creator, "Test Creator") # Check flattened name
        self.assertEqual(result.projects[0].backers, 800)           # Check aliased field
        self.assertEqual(result.projects[0].status, "successful")   # Check aliased field

        # Check that the correct API call was made
        expected_url = "https://kickstarter-data-api.p.rapidapi.com/search"
        expected_headers = {
            "X-RapidAPI-Key": "fake_rapidapi_key",
            "X-RapidAPI-Host": "kickstarter-data-api.p.rapidapi.com"
        }
        expected_params = {"query": "Test Gadget"}
        mock_get.assert_called_with(
            expected_url,
            params=expected_params,
            headers=expected_headers
        )

    @patch("chimera_intel.core.finint.API_KEYS")
    def test_analyze_crowdfunding_no_key(self, mock_api_keys):
        """Tests that the function fails gracefully if no API key is set."""
        # Arrange
        mock_api_keys.kickstarter_api_key = None

        # Act
        result = analyze_crowdfunding("Test Gadget")

        # Assert
        self.assertIsNone(result.projects)
        self.assertIsNotNone(result.error)
        self.assertIn("KICKSTARTER_API_KEY", result.error)


    @patch("chimera_intel.core.finint.analyze_crowdfunding")
    def test_cli_track_crowdfunding(self, mock_analyze_crowdfunding):
        """Tests the 'track-crowdfunding' CLI command (no change needed here)."""
        # Arrange
        mock_analyze_crowdfunding.return_value = CrowdfundingAnalysisResult(
            keyword="Test Gadget",
            projects=[
                CrowdfundingProject(
                    project_name="Test Gadget Pro",
                    url="http://example.com",
                    creator="Creator",
                    goal=1000,
                    pledged=5000,
                    backers=100,
                    status="successful",
                )
            ],
        )

        # Act
        result = runner.invoke(finint_app, ["track-crowdfunding", "Test Gadget"])

        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        mock_analyze_crowdfunding.assert_called_with("Test Gadget")
        self.assertIn("Crowdfunding Projects for 'Test Gadget'", result.stdout)
        self.assertIn("Test Gadget Pro", result.stdout)
@pytest.fixture
def mock_transactions():
    """Provides a list of mock transactions for testing."""
    return [
        FinancialTransaction(transaction_id="T1001", from_account="Acct_A", to_account="Acct_B", amount=9000, timestamp=datetime(2023, 1, 1, 10, 0, 0)),
        FinancialTransaction(transaction_id="T1003", from_account="Acct_B", to_account="Acct_D", amount=8800, timestamp=datetime(2023, 1, 2, 12, 0, 0)),
        FinancialTransaction(transaction_id="T1005", from_account="Acct_D", to_account="SUSPICIOUS_NODE_1", amount=17000, timestamp=datetime(2023, 1, 3, 14, 0, 0)),
    ]

@patch("chimera_intel.core.finint.get_transactions_from_db")
@patch("chimera_intel.core.finint.save_scan_to_db")
@patch("pyvis.network.Network.show") # Mock the actual graph file generation
def test_run_visualize_money_flow(mock_pyvis_show, mock_save_db, mock_get_tx, mock_transactions, tmp_path):
    """
    Tests the visualize-flow command.
    It should create an HTML file and highlight the specified node.
    """
    mock_get_tx.return_value = mock_transactions
    output_file = tmp_path / "money_flow.html"

    result = runner.invoke(
        finint_app,
        ["visualize-flow", "test_target", "--output", str(output_file), "--highlight", "SUSPICIOUS_NODE_1"],
    )

    assert result.exit_code == 0, f"CLI Error: {result.stdout}"
    assert "Money flow visualization saved to" in result.stdout
    assert str(output_file) in result.stdout
    mock_pyvis_show.assert_called_with(str(output_file))
    mock_save_db.assert_called_once()
    assert mock_save_db.call_args[1]["module"] == "finint_money_flow"
    assert mock_save_db.call_args[1]["data"]["suspicious_nodes"] == ["SUSPICIOUS_NODE_1"]

@patch("chimera_intel.core.finint.get_transactions_from_db")
@patch("chimera_intel.core.finint.save_scan_to_db")
@patch("chimera_intel.core.finint.analyze_transaction_patterns")
@patch("chimera_intel.core.finint.API_KEYS", MagicMock(google_api_key="test_key123"))
def test_run_aml_pattern_detection(mock_ai_analyze, mock_save_db, mock_get_tx, mock_transactions):
    """
    Tests the detect-patterns command.
    It should call the AI core function and display the results.
    """
    mock_get_tx.return_value = mock_transactions
    mock_pattern = AmlPattern(
        pattern_type="Layering",
        description="Funds moved through multiple accounts",
        involved_accounts=["Acct_A", "Acct_B", "Acct_D"],
        confidence_score=0.95,
        evidence=["T1001", "T1003"]
    )
    mock_ai_analyze.return_value = AmlAnalysisResult(
        target="test_target",
        patterns_detected=[mock_pattern],
        summary="Detected 1 pattern"
    )

    result = runner.invoke(
        finint_app,
        ["detect-patterns", "test_target"],
    )

    assert result.exit_code == 0, f"CLI Error: {result.stdout}"
    assert "AI Analysis Complete" in result.stdout
    assert "Layering" in result.stdout
    assert "Acct_A, Acct_B, Acct_D" in result.stdout
    assert "95%" in result.stdout
    mock_ai_analyze.assert_called_with("test_target", mock_transactions, "test_key123")
    mock_save_db.assert_called_once()
    assert mock_save_db.call_args[1]["module"] == "finint_aml_patterns"

@patch("chimera_intel.core.finint.get_transactions_from_db")
@patch("chimera_intel.core.finint.save_scan_to_db")
def test_run_scenario_simulation(mock_save_db, mock_get_tx, mock_transactions):
    """
    Tests the simulate-scenario command.
    It should build an in-memory graph and trace descendants.
    """
    mock_get_tx.return_value = mock_transactions

    result = runner.invoke(
        finint_app,
        ["simulate-scenario", "--node", "Acct_A", "--target", "test_target"],
    )

    assert result.exit_code == 0, f"CLI Error: {result.stdout}"
    assert "Simulation Impact Report" in result.stdout
    # Verifies the graph traversal (A -> B -> D -> SUSPICIOUS_NODE_1)
    assert "Acct_B" in result.stdout
    assert "Acct_D" in result.stdout
    assert "SUSPICIOUS_NODE_1" in result.stdout
    assert "$9,000.00" in result.stdout # Direct outflow from Acct_A
    mock_save_db.assert_called_once()
    assert mock_save_db.call_args[1]["module"] == "finint_aml_simulation"

if __name__ == "__main__":
    unittest.main()
