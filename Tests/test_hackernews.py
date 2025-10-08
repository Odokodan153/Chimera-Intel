import unittest
from src.chimera_intel.core.hackernews import HackerNews


class TestHackerNews(unittest.TestCase):
    def setUp(self):
        self.hackernews = HackerNews()

    def test_get_top_stories_live(self):
        """
        Tests the live fetching and parsing of the Hacker News feed.
        """
        articles = self.hackernews.get_top_stories(limit=5)

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
