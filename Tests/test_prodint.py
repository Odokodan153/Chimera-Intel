import unittest
from unittest.mock import patch, Mock
from src.chimera_intel.core.prodint import ProdInt


class TestProdInt(unittest.TestCase):
    def setUp(self):
        self.prodint = ProdInt()

    @patch("src.chimera_intel.core.prodint.WebPage")
    @patch("src.chimera_intel.core.prodint.Wappalyzer")
    def test_digital_teardown(self, mock_wappalyzer_class, mock_webpage_class):
        # --- Setup Mocks ---
        # Mock the WebPage object that is created

        mock_webpage_instance = Mock()
        mock_webpage_class.new_from_url.return_value = mock_webpage_instance

        # Mock the Wappalyzer instance and its analyze method

        mock_wappalyzer_instance = Mock()
        mock_wappalyzer_instance.analyze_with_versions.return_value = {
            "JavaScript Frameworks": {"React": ["18.2.0"]}
        }
        mock_wappalyzer_class.return_value = mock_wappalyzer_instance

        # --- Run Test ---

        result = self.prodint.digital_teardown("https://example.com")

        # --- Assertions ---

        self.assertIn("JavaScript Frameworks", result)
        self.assertEqual(result["JavaScript Frameworks"]["React"][0], "18.2.0")
        mock_webpage_class.new_from_url.assert_called_once_with("https://example.com")
        mock_wappalyzer_instance.analyze_with_versions.assert_called_once_with(
            mock_webpage_instance
        )

    @patch("src.chimera_intel.core.prodint.AppStore")
    def test_analyze_churn_risk(self, mock_app_store_class):
        # --- Setup Mocks ---
        # Mock the AppStore instance, its 'review' method, and 'reviews' attribute

        mock_app_store_instance = Mock()
        mock_app_store_instance.reviews = [
            {"review": "This is the best app ever!"},  # Positive
            {"review": "I hate this, it is terrible."},  # Negative
            {"review": "It is okay, not great."},  # Neutral
        ]
        mock_app_store_class.return_value = mock_app_store_instance

        # --- Run Test ---

        result = self.prodint.analyze_churn_risk("com.example.app", review_count=3)

        # --- Assertions ---

        self.assertEqual(result["reviews_analyzed"], 3)
        self.assertEqual(result["positive_sentiment"], "33.3%")
        self.assertEqual(result["negative_sentiment"], "33.3%")
        self.assertEqual(result["estimated_churn_risk"], "Medium")
        mock_app_store_class.assert_called_once_with(
            country="us", app_name="com.example.app"
        )
        mock_app_store_instance.review.assert_called_once_with(how_many=3)

    def test_find_feature_gaps(self):
        # This test is logically correct and needs no changes.

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
