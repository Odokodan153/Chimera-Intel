import pytest
import asyncio
import json
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, AsyncMock
from chimera_intel.core.rt_osint import rt_osint_app, DEDUP_FILE
import os

# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio


@pytest.fixture
def runner():
    """Provides a Typer CliRunner instance."""
    return CliRunner()

@pytest.fixture(autouse=True)
def cleanup_dedup_file():
    """Ensure the dedup file is removed before and after each test."""
    if os.path.exists(DEDUP_FILE):
        os.remove(DEDUP_FILE)
    yield
    if os.path.exists(DEDUP_FILE):
        os.remove(DEDUP_FILE)

# Mock HTML data
MOCK_HTML_BLEEPING = """
<ul id="search-results">
    <li>
        <h3><a href="https.www.bleepingcomputer.com/news/security/fbi-seizes-drug-market">FBI seizes drug market</a></h3>
    </li>
</ul>
"""
MOCK_HTML_KREBS = """
<article class="post">
    <h2 class="entry-title">
        <a href="https.krebsonsecurity.com/2023/10/new-weapon-market-emerges">New Weapon Market Emerges</a>
    </h2>
</article>
"""
MOCK_HTML_AHMIA = """
<ol>
    <li class="result">
        <h4><a href="/redirect?q=http://exampleonion123.onion">Example Gun Market</a></h4>
        <cite>http://exampleonion123.onion</cite>
    </li>
</ol>
"""
MOCK_HTML_TOR_CHECK = json.dumps({"IsTor": True, "IP": "1.2.3.4"})


async def mock_get_side_effect(url, *args, **kwargs):
    """A reusable mock for aiohttp.get()."""
    mock_resp = AsyncMock()
    mock_resp.status = 200
    if "check.torproject.org" in url:
        mock_resp.text.return_value = MOCK_HTML_TOR_CHECK
    elif "bleepingcomputer.com" in url:
        # Check which keyword is being searched
        if "drug" in url:
            mock_resp.text.return_value = MOCK_HTML_BLEEPING
        else:
            mock_resp.text.return_value = ""
    elif "krebsonsecurity.com" in url:
        if "weapon" in url:
            mock_resp.text.return_value = MOCK_HTML_KREBS
        else:
            mock_resp.text.return_value = ""
    elif "ahmia.fi" in url:
        if "pistol" in url:
             mock_resp.text.return_value = MOCK_HTML_AHMIA
        else:
            mock_resp.text.return_value = ""
    else:
        mock_resp.text.return_value = ""
    
    mock_resp.__aenter__.return_value = mock_resp
    return mock_resp


class TestRealTimeOsint:

    @patch('chimera_intel.core.rt_osint.asyncio.sleep', new_callable=AsyncMock)
    @patch('chimera_intel.core.rt_osint.aiohttp.ClientSession')
    @patch('chimera_intel.core.rt_osint.ProxyConnector.from_url')
    async def test_monitor_command_success_default_keywords(self, mock_connector, mock_session, mock_sleep, runner):
        """Tests the 'rt-osint monitor' command with default --keywords."""
        
        mock_sleep.side_effect = KeyboardInterrupt
        
        mock_get = AsyncMock(side_effect=mock_get_side_effect)
        mock_session_instance = MagicMock()
        mock_session_instance.get = mock_get
        mock_session_instance.__aenter__.return_value = mock_session_instance
        mock_session_instance.__aexit__.return_value = None
        mock_session.return_value = mock_session_instance

        # Act
        result = runner.invoke(
            rt_osint_app,
            ["monitor", "-k", "drug,weapon,pistol", "-i", "1"]
        )
        
        # Assert
        assert result.exit_code == 0
        output = result.stdout
        
        assert "Loading keywords from command line argument." in output
        assert "Tor Connection Verified." in output
        assert "FBI seizes drug market" in output
        assert "New Weapon Market Emerges" in output
        assert "Example Gun Market" in output
        assert "http://exampleonion123.onion" in output
        assert os.path.exists(DEDUP_FILE)

    @patch('chimera_intel.core.rt_osint.perform_checks', new_callable=AsyncMock)
    async def test_monitor_command_with_keyword_file(self, mock_perform_checks, runner, tmp_path):
        """Tests that the --keyword-file option correctly loads and passes keywords."""
        
        # --- Arrange ---
        # 1. Create a temporary keyword file
        keyword_file = tmp_path / "test_keywords.txt"
        keyword_file.write_text("file_keyword_1\n# this is a comment\n\nfile_keyword_2\n")
        
        # 2. We mock the whole perform_checks function to just check its inputs
        mock_perform_checks.side_effect = KeyboardInterrupt # Stop the run
        
        # --- Act ---
        result = runner.invoke(
            rt_osint_app,
            ["monitor", "--keyword-file", str(keyword_file), "-i", "1"]
        )

        # --- Assert ---
        assert result.exit_code == 0
        assert f"Loading keywords from file: [cyan]{keyword_file}[/cyan]" in result.stdout
        
        # Verify perform_checks was called with the keywords from the file
        mock_perform_checks.assert_called_once()
        args, kwargs = mock_perform_checks.call_args
        # args[0] is 'proxy', args[1] is 'keyword_list', args[2] is 'interval'
        assert args[1] == ["file_keyword_1", "file_keyword_2"]
        # Verify it did NOT use the default keywords
        assert "cocaine" not in args[1]

    async def test_monitor_keyword_file_not_found(self, runner):
        """Tests the error case for a missing keyword file."""
        # --- Act ---
        result = runner.invoke(
            rt_osint_app,
            ["monitor", "--keyword-file", "non_existent_file.txt", "-i", "1"]
        )
        
        # --- Assert ---
        assert result.exit_code == 1 # Typer.Exit(code=1)
        assert "Error: Keyword file not found at 'non_existent_file.txt'" in result.stdout

    async def test_monitor_keyword_file_empty(self, runner, tmp_path):
        """Tests the error case for an empty or commented-out keyword file."""
        # --- Arrange ---
        keyword_file = tmp_path / "empty_keywords.txt"
        keyword_file.write_text("# just a comment\n\n# another comment\n")
        
        # --- Act ---
        result = runner.invoke(
            rt_osint_app,
            ["monitor", "--keyword-file", str(keyword_file), "-i", "1"]
        )
        
        # --- Assert ---
        assert result.exit_code == 1
        assert "Error: Keyword file" in result.stdout
        assert "is empty or only contains comments" in result.stdout

    @patch('chimera_intel.core.rt_osint.asyncio.sleep', new_callable=AsyncMock)
    @patch('chimera_intel.core.rt_osint.aiohttp.ClientSession')
    @patch('chimera_intel.core.rt_osint.ProxyConnector.from_url')
    async def test_monitor_tor_connection_failed(self, mock_connector, mock_session, mock_sleep, runner):
        """Tests that the monitor aborts if the Tor connection check fails."""
        
        mock_sleep.side_effect = KeyboardInterrupt
        
        mock_get = AsyncMock()
        mock_tor_fail_resp = json.dumps({"IsTor": False, "IP": "1.2.3.4"})
        async def get_side_effect(url, *args, **kwargs):
            mock_resp = AsyncMock()
            mock_resp.status = 200
            if "check.torproject.org" in url:
                mock_resp.text.return_value = mock_tor_fail_resp
            else:
                mock_resp.text.return_value = ""
            mock_resp.__aenter__.return_value = mock_resp
            return mock_resp
        
        mock_get.side_effect = get_side_effect
        
        mock_session_instance = MagicMock()
        mock_session_instance.get = mock_get
        mock_session_instance.__aenter__.return_value = mock_session_instance
        mock_session.return_value = mock_session_instance

        # --- Act ---
        result = runner.invoke(rt_osint_app, ["monitor", "-i", "1"])
        
        # --- Assert ---
        assert result.exit_code == 0 # Graceful exit
        output = result.stdout
        assert "Tor Connection Verified." not in output
        assert "[bold red]Connection failed:[/bold red] Not connected to Tor." in output
        assert "No new results" not in output # Loop should not run