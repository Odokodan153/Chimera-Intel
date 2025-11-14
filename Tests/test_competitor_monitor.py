import unittest
from unittest.mock import patch, MagicMock
import json

from chimera_intel.core.competitor_monitor import (
    monitor_competitor_activity,
    _generate_keywords
)
from chimera_intel.core.schemas import (
    ProjectConfig,
    GitHubLeaksResult,
    GitHubLeakItem,
    PasteMonitorResult,
    PasteLeak,
    DarkWebScanResult,
    DarkWebResult
)

class TestCompetitorMonitor(unittest.TestCase):
    """Test cases for the new competitor leak monitor."""

    def test_generate_keywords(self):
        """Tests the keyword generation helper."""
        keywords = _generate_keywords("EvilCorp")
        self.assertIn('"EvilCorp"', keywords)
        self.assertIn('"EvilCorp" internal', keywords)
        self.assertIn('"EvilCorp" leak', keywords)
        self.assertIn('"EvilCorp" database', keywords)

        keywords_multi = _generate_keywords("The Other Guys")
        self.assertIn('"The Other Guys"', keywords_multi)
        self.assertIn('"The Other Guys" confidential', keywords_multi)
        # Should not use "The" as a keyword
        self.assertNotIn('"The" database', keywords_multi)

    @patch("chimera_intel.core.competitor_monitor.get_project_config_by_name")
    @patch("chimera_intel.core.competitor_monitor._get_seen_leak_urls")
    @patch("chimera_intel.core.competitor_monitor.search_github_leaks")
    @patch("chimera_intel.core.competitor_monitor.search_pastebins")
    @patch("chimera_intel.core.competitor_monitor.search_dark_web")
    @patch("chimera_intel.core.competitor_monitor.alert_manager_instance.dispatch_alert")
    @patch("chimera_intel.core.competitor_monitor.save_scan_to_db")
    def test_monitor_finds_new_leaks(
        self, mock_save_db, mock_dispatch_alert, mock_dark_web, 
        mock_pastebins, mock_github, mock_get_seen, mock_get_config
    ):
        """Tests that new, unseen leaks trigger alerts and a DB save."""
        # Arrange
        project_name = "TestProject"
        competitor_name = "EvilCorp"
        
        # 1. Config: Return a project with one competitor
        mock_get_config.return_value = ProjectConfig(
            project_name=project_name, 
            created_at="...",
            competitors=[competitor_name]
        )
        
        # 2. DB: Return no previously seen URLs
        mock_get_seen.return_value = set()
        
        # 3. Mocks for search functions
        mock_github.return_value = GitHubLeaksResult(
            items=[GitHubLeakItem(url="http://github.com/leak/1", repository="repo1")]
        )
        mock_pastebins.return_value = PasteMonitorResult(
            leaks_found=[PasteLeak(
                id="p1", 
                source="Pastebin", 
                url="http://pastebin.com/1", 
                content_snippet="pass=", 
                matched_keyword="EvilCorp"
            )]
        )
        mock_dark_web.return_value = DarkWebScanResult(
            query=competitor_name,
            found_results=[DarkWebResult(
                title="EvilCorp Leak", 
                url="http://dark.web/1", 
                description="secrets"
            )]
        )

        # Act
        monitor_competitor_activity(project_name)

        # Assert
        # 1. Should be 3 alerts (one for each source)
        self.assertEqual(mock_dispatch_alert.call_count, 3)
        
        # Check GitHub alert
        mock_dispatch_alert.assert_any_call(
            title="New Code Leak: EvilCorp",
            message=unittest.mock.ANY,
            level="WARNING",
            provenance={'module': 'competitor_monitor', 'project': 'TestProject', 'competitor': 'EvilCorp'}
        )
        
        # Check Pastebin alert
        mock_dispatch_alert.assert_any_call(
            title="New Pastebin Leak: EvilCorp",
            message=unittest.mock.ANY,
            level="WARNING",
            provenance={'module': 'competitor_monitor', 'project': 'TestProject', 'competitor': 'EvilCorp'}
        )

        # Check Dark Web alert
        mock_dispatch_alert.assert_any_call(
            title="New Dark Web Mention: EvilCorp",
            message=unittest.mock.ANY,
            level="CRITICAL",
            provenance={'module': 'competitor_monitor', 'project': 'TestProject', 'competitor': 'EvilCorp'}
        )

        # 2. Check that the new run was saved to the DB
        mock_save_db.assert_called_once()
        saved_data = mock_save_db.call_args[1]['data']
        self.assertEqual(len(saved_data['new_findings']), 3)
        self.assertIn("http://github.com/leak/1", saved_data['all_seen_leak_urls'])
        self.assertIn("http://pastebin.com/1", saved_data['all_seen_leak_urls'])
        self.assertIn("http://dark.web/1", saved_data['all_seen_leak_urls'])

    @patch("chimera_intel.core.competitor_monitor.get_project_config_by_name")
    @patch("chimera_intel.core.competitor_monitor._get_seen_leak_urls")
    @patch("chimera_intel.core.competitor_monitor.search_github_leaks")
    @patch("chimera_intel.core.competitor_monitor.search_pastebins")
    @patch("chimera_intel.core.competitor_monitor.search_dark_web")
    @patch("chimera_intel.core.competitor_monitor.alert_manager_instance.dispatch_alert")
    @patch("chimera_intel.core.competitor_monitor.save_scan_to_db")
    def test_monitor_ignores_seen_leaks(
        self, mock_save_db, mock_dispatch_alert, mock_dark_web, 
        mock_pastebins, mock_github, mock_get_seen, mock_get_config
    ):
        """Tests that previously seen leaks do not trigger alerts."""
        # Arrange
        project_name = "TestProject"
        competitor_name = "EvilCorp"
        seen_url = "http://github.com/leak/1"
        
        mock_get_config.return_value = ProjectConfig(
            project_name=project_name, 
            created_at="...",
            competitors=[competitor_name]
        )
        
        # 2. DB: Return the URL as already seen
        mock_get_seen.return_value = {seen_url}
        
        # 3. Mocks for search functions (return the same seen URL)
        mock_github.return_value = GitHubLeaksResult(
            items=[GitHubLeakItem(url=seen_url, repository="repo1")]
        )
        mock_pastebins.return_value = PasteMonitorResult(leaks_found=[])
        mock_dark_web.return_value = DarkWebScanResult(found_results=[])

        # Act
        monitor_competitor_activity(project_name)

        # Assert
        # 1. No alerts should be dispatched
        mock_dispatch_alert.assert_not_called()
        
        # 2. No new data should be saved to the DB
        mock_save_db.assert_not_called()

if __name__ == "__main__":
    unittest.main()