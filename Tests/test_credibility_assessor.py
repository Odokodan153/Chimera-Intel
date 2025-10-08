import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from chimera_intel.core.credibility_assessor import assess_source_credibility
from chimera_intel.core.schemas import CredibilityResult
from datetime import datetime


class TestCredibilityAssessor(unittest.TestCase):
    """Test cases for the credibility_assessor module."""

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
        mock_whois.return_value.creation_date = datetime(2010, 1, 1)
        mock_safe_browsing.return_value = {}

        result = await assess_source_credibility("https://www.example.com")
        self.assertIsInstance(result, CredibilityResult)
        self.assertGreater(result.credibility_score, 7.5)
        self.assertIsNone(result.error)

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
        mock_response.text = "<html><body></body></html>"
        mock_get.return_value = mock_response
        mock_whois.return_value.creation_date = datetime.now()
        mock_safe_browsing.return_value = {"matches": [{"threatType": "MALWARE"}]}

        result = await assess_source_credibility("http://www.malicious-site.com")
        self.assertIsInstance(result, CredibilityResult)
        self.assertLess(result.credibility_score, 2.0)
        self.assertIn(
            "URL is flagged by Google Safe Browsing as potentially malicious.",
            result.factors,
        )

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
        mock_whois.return_value.creation_date = datetime(2018, 1, 1)
        mock_safe_browsing.return_value = {}

        result = await assess_source_credibility("https://www.clickbait-news.com")
        self.assertIsInstance(result, CredibilityResult)
        self.assertIn("Clickbait phrases found in content.", result.factors)


if __name__ == "__main__":
    unittest.main()
