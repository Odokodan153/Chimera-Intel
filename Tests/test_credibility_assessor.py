import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from chimera_intel.core.credibility_assessor import (
    assess_source_credibility,
    check_google_safe_browsing,
)
from chimera_intel.core.schemas import CredibilityResult
from datetime import datetime
import httpx
from typer.testing import CliRunner
# FIX: Import the sub-app from credibility_assessor.py, not the main app
from chimera_intel.core.credibility_assessor import app as credibility_app

# Use unittest.IsolatedAsyncioTestCase for async test methods
class TestCredibilityAssessor(unittest.IsolatedAsyncioTestCase):
    """Test cases for the credibility_assessor module."""

    @patch("chimera_intel.core.credibility_assessor.API_KEYS")
    async def test_check_google_safe_browsing_no_key(self, mock_api_keys):
        """Tests Google Safe Browsing check when API key is missing."""
        mock_api_keys.google_api_key = None
        result = await check_google_safe_browsing("https://www.example.com")
        self.assertIsNone(result)

    @patch("chimera_intel.core.credibility_assessor.API_KEYS")
    @patch("chimera_intel.core.credibility_assessor.httpx.AsyncClient.post", new_callable=AsyncMock)
    async def test_check_google_safe_browsing_api_error(self, mock_post, mock_api_keys):
        """Tests Google Safe Browsing check during an API error."""
        mock_api_keys.google_api_key = "fake_key"
        mock_post.side_effect = httpx.HTTPStatusError(
            "API Error", request=MagicMock(), response=MagicMock()
        )
        result = await check_google_safe_browsing("https://www.example.com")
        self.assertIsNone(result)

    @patch(
        "chimera_intel.core.credibility_assessor.check_google_safe_browsing",
        new_callable=AsyncMock,
    )
    @patch("chimera_intel.core.credibility_assessor.whois.whois")
    @patch(
        "chimera_intel.core.credibility_assessor.httpx.AsyncClient.get",
        new_callable=AsyncMock,
    )
    async def test_assess_highly_credible_source(
        self, mock_get, mock_whois, mock_safe_browsing
    ):
        """Tests a highly credible source."""
        mock_response = MagicMock()
        mock_response.text = '<html><body><a href="https://twitter.com/example">Twitter</a></body></html>'
        mock_get.return_value = mock_response

        # Mock whois response
        mock_whois_info = MagicMock()
        mock_whois_info.creation_date = datetime(2010, 1, 1)
        mock_whois.return_value = mock_whois_info

        mock_safe_browsing.return_value = {}

        result = await assess_source_credibility("https://www.example.com")
        self.assertIsInstance(result, CredibilityResult)
        self.assertGreater(result.credibility_score, 7.5)
        self.assertIsNone(result.error)
        self.assertIn("SSL certificate is present.", result.factors)
        # FIX: Check if the factor *starts with* the text, to account for the dynamic age
        self.assertTrue(any(f.startswith("Domain is mature") for f in result.factors))
        self.assertIn("URL is not flagged by Google Safe Browsing.", result.factors)
        self.assertIn("Social media presence detected.", result.factors)

    @patch(
        "chimera_intel.core.credibility_assessor.check_google_safe_browsing",
        new_callable=AsyncMock,
    )
    @patch("chimera_intel.core.credibility_assessor.whois.whois")
    @patch(
        "chimera_intel.core.credibility_assessor.httpx.AsyncClient.get",
        new_callable=AsyncMock,
    )
    async def test_assess_malicious_source(
        self, mock_get, mock_whois, mock_safe_browsing
    ):
        """Tests a source flagged as malicious."""
        mock_response = MagicMock()
        mock_response.text = "<html><body><iframe src='ad.html'></iframe><iframe src='ad.html'></iframe><iframe src='ad.html'></iframe><iframe src='ad.html'></iframe><iframe src='ad.html'></iframe><iframe src='ad.html'></iframe></body></html>"  # > 5 iframes
        mock_get.return_value = mock_response

        # Mock whois response for a new domain
        mock_whois_info = MagicMock()
        mock_whois_info.creation_date = datetime.now()
        mock_whois.return_value = mock_whois_info

        mock_safe_browsing.return_value = {"matches": [{"threatType": "MALWARE"}]}

        result = await assess_source_credibility("http://www.malicious-site.com")
        self.assertIsInstance(result, CredibilityResult)
        self.assertLess(result.credibility_score, 2.0)
        # FIX: Check if the factor *starts with* the text
        self.assertTrue(any(f.startswith("No SSL certificate") for f in result.factors))
        self.assertTrue(any(f.startswith("Domain is very new") for f in result.factors))
        self.assertIn(
            "URL is flagged by Google Safe Browsing as potentially malicious.",
            result.factors,
        )
        self.assertIn("Excessive number of ads detected.", result.factors)

    @patch(
        "chimera_intel.core.credibility_assessor.check_google_safe_browsing",
        new_callable=AsyncMock,
    )
    @patch("chimera_intel.core.credibility_assessor.whois.whois")
    @patch(
        "chimera_intel.core.credibility_assessor.httpx.AsyncClient.get",
        new_callable=AsyncMock,
    )
    async def test_assess_clickbait_source(
        self, mock_get, mock_whois, mock_safe_browsing
    ):
        """Tests a source with clickbait."""
        mock_response = MagicMock()
        mock_response.text = (
            "<html><body><h1>You won't believe this shocking secret!</h1></body></html>"
        )
        mock_get.return_value = mock_response

        # Mock whois for a domain between 1 and 2 years old
        mock_whois_info = MagicMock()
        mock_whois_info.creation_date = datetime(
            datetime.now().year - 1, datetime.now().month, datetime.now().day
        )
        mock_whois.return_value = mock_whois_info

        mock_safe_browsing.return_value = {}

        result = await assess_source_credibility("https://www.clickbait-news.com")
        self.assertIsInstance(result, CredibilityResult)
        self.assertIn("Clickbait phrases found in content.", result.factors)
        # FIX: Check if the factor *starts with* the text
        self.assertTrue(any(f.startswith("Domain is relatively new") for f in result.factors))
        
    @patch("chimera_intel.core.credibility_assessor.urlparse", side_effect=Exception("Test Error"))
    async def test_assess_source_general_exception(self, mock_urlparse):
        """Tests the general exception handler for assess_source_credibility."""
        result = await assess_source_credibility("https://www.example.com")
        self.assertEqual(result.credibility_score, 0.0)
        self.assertIn("An error occurred: Test Error", result.error)

    @patch("chimera_intel.core.credibility_assessor.whois.whois", side_effect=Exception("WHOIS Error"))
    @patch("chimera_intel.core.credibility_assessor.check_google_safe_browsing", new_callable=AsyncMock, return_value={})
    @patch("chimera_intel.core.credibility_assessor.httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_assess_source_whois_exception(self, mock_get, mock_safe_browsing, mock_whois):
        """Tests exception handling during the whois lookup."""
        mock_response = MagicMock()
        mock_response.text = "<html><body></body></html>"
        mock_get.return_value = mock_response

        result = await assess_source_credibility("https://www.example.com")
        self.assertIsInstance(result, CredibilityResult)
        self.assertIsNone(result.error)
        self.assertIn("Could not determine domain age.", result.factors)

    # --- CLI Tests ---
    
    def setUp(self):
        self.runner = CliRunner()

    @patch("chimera_intel.core.credibility_assessor.asyncio.run")
    def test_cli_assess_success_high_score(self, mock_asyncio_run):
        """Tests the CLI for a high score."""
        mock_result = CredibilityResult(
            url="https://example.com",
            credibility_score=8.5,
            factors=["Factor 1", "Factor 2"],
            error=None,
        )
        mock_asyncio_run.return_value = mock_result
        
        # FIX: Added required URL argument
        result = self.runner.invoke(credibility_app, ["assess", "https://example.com"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Credibility Score: 8.5/10.0", result.stdout)
        self.assertIn("Factor 1", result.stdout)
        # FIX: Check for title instead of unreliable color
        self.assertIn("Credibility Assessment for https://example.com", result.stdout)

    @patch("chimera_intel.core.credibility_assessor.asyncio.run")
    def test_cli_assess_success_medium_score(self, mock_asyncio_run):
        """Tests the CLI for a medium score."""
        mock_result = CredibilityResult(
            url="https://example.com",
            credibility_score=5.5,
            factors=["Factor 1"],
            error=None,
        )
        mock_asyncio_run.return_value = mock_result
        
        # FIX: Added required URL argument
        result = self.runner.invoke(credibility_app, ["assess", "https://example.com"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Credibility Score: 5.5/10.0", result.stdout)
        # FIX: Check for title instead of unreliable color
        self.assertIn("Credibility Assessment for https://example.com", result.stdout)

    @patch("chimera_intel.core.credibility_assessor.asyncio.run")
    def test_cli_assess_success_low_score(self, mock_asyncio_run):
        """Tests the CLI for a low score."""
        mock_result = CredibilityResult(
            url="http.example.com",
            credibility_score=2.0,
            factors=["Factor 1"],
            error=None,
        )
        mock_asyncio_run.return_value = mock_result
        
        # FIX: Added required URL argument
        result = self.runner.invoke(credibility_app, ["assess", "https://example.com"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Credibility Score: 2.0/10.0", result.stdout)
        # FIX: Check for title instead of unreliable color
        self.assertIn("Credibility Assessment for https://example.com", result.stdout)

    @patch("chimera_intel.core.credibility_assessor.asyncio.run")
    def test_cli_assess_error(self, mock_asyncio_run):
        """Tests the CLI when an error occurs during assessment."""
        mock_result = CredibilityResult(
            url="https.example.com",
            credibility_score=0.0,
            factors=[],
            error="A test error occurred",
        )
        mock_asyncio_run.return_value = mock_result
        
        # FIX: Added required URL argument
        result = self.runner.invoke(credibility_app, ["assess", "https://example.com"])
        # The command prints an error but exits cleanly (code 0)
        self.assertEqual(result.exit_code, 0) 
        self.assertIn("Error:", result.stdout)
        self.assertIn("A test error occurred", result.stdout)

    def test_cli_no_args(self):
        """Tests the CLI when no arguments are provided to the subcommand."""
        # FIX: Invoke the local credibility_app to trigger "no_args_is_help"
        result = self.runner.invoke(credibility_app, [])
        # FIX: Assert that no_args_is_help=True works: exits 0 and prints help
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Usage: ", result.stdout)


if __name__ == "__main__":
    unittest.main()