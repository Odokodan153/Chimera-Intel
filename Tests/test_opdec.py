# Tests/test_opdec.py

import unittest
import asyncio
from unittest.mock import MagicMock, patch, declarative_base

# Mock modules before they are imported by opdec
mock_db = MagicMock()
mock_http_client = MagicMock()
mock_rt_osint = MagicMock()
mock_web_scraper = MagicMock()
mock_footprint = MagicMock()
mock_synth_media = MagicMock()

# Mock Base for SQLAlchemy
MockBase = declarative_base()

module_patches = {
    'src.chimera_intel.core.database': mock_db,
    'src.chimera_intel.core.http_client': mock_http_client,
    'src.chimera_intel.core.rt_osint': mock_rt_osint,
    'src.chimera_intel.core.web_scraper': mock_web_scraper,
    'src.chimera_intel.core.footprint': mock_footprint,
    'src.chimera_intel.core.synthetic_media_generator': mock_synth_media,
}

# Apply patches
with patch.dict('sys.modules', module_patches):
    from src.chimera_intel.core.opdec import (
        proxied_web_scrape,
        _generate_plausible_target,
        generate_chaff_traffic,
        create_honey_profiles,
        HoneyProfile,
    )
    from src.chimera_intel.core.schemas import WebScrapeResult

class TestOPDECEngine(unittest.TestCase):

    def setUp(self):
        # Reset mocks before each test
        mock_db.reset_mock()
        mock_http_client.reset_mock()
        mock_rt_osint.reset_mock()
        mock_web_scraper.reset_mock()
        mock_synth_media.reset_mock()
        
        # Mock DB setup
        mock_db.SessionLocal = MagicMock()
        mock_db.Base = MockBase
        self.mock_session = MagicMock()
        mock_db.SessionLocal.return_value = self.mock_session

        # Mock Proxy Pool
        mock_rt_osint.get_proxy_pool.return_value = ["http://proxy1.com:8080"]

        # Mock HTTP Client
        self.mock_client = MagicMock()
        mock_http_client.get_http_client.return_value = self.mock_client
        
        # Mock Synthetic Persona
        mock_synth_media.generate_synthetic_persona.return_value = {
            "name": "John Doe",
            "user_agent": "Test-UA-1.0",
            "bio": "Test bio"
        }
        
        # Mock Honey Profile DB Query
        self.mock_profile = HoneyProfile(name="DB Profile", user_agent="DB-UA-1.0")
        mock_query = MagicMock()
        mock_query.order_by.return_value.first.return_value = self.mock_profile
        self.mock_session.query.return_value = mock_query

    def test_generate_plausible_target(self):
        target = _generate_plausible_target()
        self.assertTrue(target.endswith(".com") or target.endswith(".org") or
                        target.endswith(".net") or target.endswith(".info"))
        self.assertIn("-", target)

    def test_create_honey_profiles(self):
        create_honey_profiles(count=2)
        
        # Check that synthetic persona was called twice
        self.assertEqual(mock_synth_media.generate_synthetic_persona.call_count, 2)
        
        # Check that profiles were added to session
        self.assertEqual(self.mock_session.add.call_count, 2)
        
        # Check that session was committed
        self.mock_session.commit.assert_called_once()

    def test_proxied_web_scrape_full_flow(self):
        
        # Mock the *real* scrape function to return a successful result
        async def mock_real_scrape(client, url):
            return WebScrapeResult(url=url, content="success", status_code=200)
            
        mock_web_scraper.real_scrape_page = MagicMock(side_effect=mock_real_scrape)

        test_url = "http://example.com"
        
        # We need to patch asyncio.create_task to verify chaff is called
        with patch('asyncio.create_task') as mock_create_task:
            
            # Run the async function
            result = asyncio.run(proxied_web_scrape(test_url))
            
            # 1. Check result
            self.assertEqual(result.content, "success")
            
            # 2. Check Chaff Generation was spawned
            mock_create_task.assert_called_once()
            
            # 3. Check Proxy was fetched
            mock_rt_osint.get_proxy_pool.assert_called_once()
            
            # 4. Check Honey-Profile was fetched
            self.mock_session.query.assert_called_with(HoneyProfile)
            
            # 5. Check HTTP Client was created with proxy AND honey-profile headers
            mock_http_client.get_http_client.assert_called_once_with(
                proxy="http://proxy1.com:8080",
                headers={"User-Agent": "DB-UA-1.0"}
            )
            
            # 6. Check Real Scraper was called with the correct client and URL
            mock_web_scraper.real_scrape_page.assert_called_once_with(
                client=self.mock_client,
                url=test_url
            )

    @patch('src.chimera_intel.core.opdec._get_random_proxy', MagicMock(return_value="http://proxy.com"))
    @patch('src.chimera_intel.core.http_client.get_http_client')
    def test_generate_chaff_traffic(self, mock_get_client):
        # Mock the async http client's get call
        mock_client = MagicMock()
        
        async def mock_scrape(client, url):
            return WebScrapeResult(url=url, content="", status_code=200)
            
        mock_web_scraper.real_scrape_page = MagicMock(side_effect=mock_scrape)
        
        # Run the chaff generation
        asyncio.run(generate_chaff_traffic(chaff_count=3))
        
        # Check that we tried to scrape 3 times
        self.assertEqual(mock_web_scraper.real_scrape_page.call_count, 3)
        

if __name__ == "__main__":
    unittest.main()