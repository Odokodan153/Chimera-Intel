import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from chimera_intel.core.pastebin_monitor import pastebin_app, monitor_paste_sites

runner = CliRunner()

def test_monitor_paste_sites_placeholder():
    """Tests the placeholder logic for paste site monitoring."""
    
    # Test keyword match
    keywords_keyword = ["DB_PASSWORD"]
    result_keyword = monitor_paste_sites(keywords_keyword)
    assert result_keyword.total_leaks > 0
    assert any(leak.leak_type == "KEYWORD" for leak in result_keyword.leaks_found)

    # Test regex match
    keywords_regex = ["some_other_keyword"]
    result_regex = monitor_paste_sites(keywords_regex)
    assert result_regex.total_leaks > 0
    assert any(leak.leak_type == "API_KEY" for leak in result_regex.leaks_found)
    assert any(leak.leak_type == "PASSWORD" for leak in result_regex.leaks_found)
    
    # Test no match
    keywords_none = ["nomatch123"]
    result_none = monitor_paste_sites(keywords_none)
    # The regex patterns will still match in the placeholder
    assert result_none.total_leaks > 0
    assert any(leak.leak_type == "API_KEY" for leak in result_none.leaks_found)
    assert not any(leak.leak_type == "KEYWORD" for leak in result_none.leaks_found)


@patch("chimera_intel.core.pastebin_monitor.monitor_paste_sites")
@patch("chimera_intel.core.pastebin_monitor.save_scan_to_db")
def test_run_paste_scan_cli(mock_db, mock_monitor):
    """Test the 'scan' CLI command for paste-monitor."""
    
    mock_leak = MagicMock(
        leak_type="API_KEY", 
        url="http://paste.example.com/1", 
        matched_keyword="xkeys-123",
        model_dump=MagicMock(return_value={"leak_type": "API_KEY"})
    )
    
    mock_monitor.return_value = MagicMock(
        total_leaks=1,
        leaks_found=[mock_leak],
        model_dump=MagicMock(return_value={"total_leaks": 1})
    )
    
    result = runner.invoke(pastebin_app, ["scan", "mycompany.com", "ProjectX"])
    
    assert result.exit_code == 0
    assert "Scanning paste sites" in result.stdout
    assert "mycompany.com" in result.stdout
    assert "Warning: Found 1" in result.stdout
    assert "API_KEY" in result.stdout
    assert "http://paste.example.com/1" in result.stdout
    
    mock_monitor.assert_called_with(["mycompany.com", "ProjectX"])
    mock_db.assert_called_once()