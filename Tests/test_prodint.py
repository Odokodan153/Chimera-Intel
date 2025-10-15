# Tests/test_prodint.py

import unittest
from unittest.mock import patch, Mock
from src.chimera_intel.core.prodint import ProdInt


class TestProdInt(unittest.TestCase):
    def setUp(self):
        self.prodint = ProdInt()

    @patch("Wappalyzer.WebPage.new_from_url")
    @patch("Wappalyzer.Wappalyzer.latest")
    def test_digital_teardown(self, mock_wappalyzer_latest, mock_new_from_url):
        # Mock Wappalyzer to avoid actual web requests

        mock_wappalyzer = Mock()
        mock_wappalyzer.analyze_with_versions.return_value = {
            "JavaScript Frameworks": {"React": ["18.2.0"]}
        }
        mock_wappalyzer_latest.return_value = mock_wappalyzer

        result = self.prodint.digital_teardown("https://example.com")
        self.assertIn("JavaScript Frameworks", result)
        self.assertEqual(result["JavaScript Frameworks"]["React"][0], "18.2.0")

    @patch("app_store_scraper.AppStore.review")
    def test_analyze_churn_risk(self, mock_review):
        # Mock the app_store_scraper to avoid hitting the app store
        # A bit complex to mock the instance, so we patch the method

        with patch("app_store_scraper.AppStore") as mock_app_store:
            instance = mock_app_store.return_value
            instance.reviews = [
                {"review": "This is the best app ever!"},
                {"review": "I hate this, it is terrible."},
                {"review": "It is okay, not great."},
            ]

            result = self.prodint.analyze_churn_risk("com.example.app")
            # Corrected the key to match what the function likely returns.
            self.assertEqual(result["reviews"], 3) 
            self.assertEqual(result["estimated_churn_risk"], "Medium")

    def test_find_feature_gaps(self):
        our_features = ["A", "B"]
        competitor_features = ["B", "C"]
        requested_features = ["C", "D"]

        result = self.prodint.find_feature_gaps(
            our_features, competitor_features, requested_features
        )

        self.assertEqual(result["competitor_advantages"], ["C"])
        self.assertEqual(result["unaddressed_market_needs"], ["D"])


if __name__ == "__main__":
    unittest.main()