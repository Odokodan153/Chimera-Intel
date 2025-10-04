import unittest
from src.chimera_intel.core.ainews import AiNews


class TestAiNews(unittest.TestCase):
    def setUp(self):
        self.ainews = AiNews()

    def test_get_latest_ai_news_live(self):
        """
        Tests the live fetching and parsing of the AI news feed.
        """
        articles = self.ainews.get_latest_ai_news(limit=5)

        # Check that the function returns a list

        self.assertIsInstance(articles, list)

        # If articles are found, check the structure of the first one

        if articles:
            self.assertIn("title", articles[0])
            self.assertIn("author", articles[0])
            self.assertIn("published", articles[0])
            self.assertIn("link", articles[0])


if __name__ == "__main__":
    unittest.main()
