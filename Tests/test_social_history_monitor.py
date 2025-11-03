import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, mock_open
import unittest
import os
from chimera_intel.core.social_history_monitor import monitor_profile_changes, PROFILE_DB_PATH

# Mock BS4 before import
mock_bs4 = MagicMock()
mock_soup = MagicMock()
mock_bs4.BeautifulSoup.return_value = mock_soup

@pytest.fixture(scope="module")
def mock_bs4_lib(module_mocker):
    module_mocker.patch.dict("sys.modules", {"bs4": mock_bs4})
    module_mocker.patch("chimera_intel.core.social_history_monitor.BS4_AVAILABLE", True)
    yield mock_bs4


runner = CliRunner()

@pytest.fixture(autouse=True)
def cleanup_db():
    """Ensures the mock profile db is clean before/after tests."""
    # This runs before each test
    if os.path.exists(PROFILE_DB_PATH):
        for f in os.listdir(PROFILE_DB_PATH):
            os.remove(os.path.join(PROFILE_DB_PATH, f))
    
    yield # Run the test
    
    # This runs after each test
    if os.path.exists(PROFILE_DB_PATH):
        for f in os.listdir(PROFILE_DB_PATH):
            os.remove(os.path.join(PROFILE_DB_PATH, f))
        os.rmdir(PROFILE_DB_PATH)


@patch("chimera_intel.core.social_history_monitor.requests.get")
@patch("chimera_intel.core.social_history_monitor.os.makedirs")
def test_monitor_profile_initial_save(mock_makedirs, mock_requests_get, mock_bs4_lib, cleanup_db):
    """Tests that the first run correctly saves the initial state."""
    # Arrange
    mock_response = MagicMock(text="<html><body>Profile Bio Here</body></html>")
    mock_response.raise_for_status.return_value = None
    mock_requests_get.return_value = mock_response
    mock_soup.stripped_strings = ["Profile", "Bio", "Here"] # Mock parsed text

    target_name = "test_target"
    url = "https.example.com/profile"
    db_file = os.path.join(PROFILE_DB_PATH, f"{target_name}.txt")

    # Act
    # Use mock_open to patch 'open' inside the function
    with patch("builtins.open", mock_open()) as mocked_file:
        result = monitor_profile_changes(url, target_name)

    # Assert
    mock_requests_get.assert_called_with(url, headers=unittest.mock.ANY, timeout=10)
    mock_makedirs.assert_called_with(PROFILE_DB_PATH, exist_ok=True)
    assert not os.path.exists(db_file) # mock_open prevents actual file creation
    mocked_file.assert_called_once_with(db_file, "w", encoding="utf-8")
    mocked_file().write.assert_called_once_with("Profile Bio Here")
    
    assert result.error is None
    assert result.changes_found is False
    assert "Initial profile state saved" in result.status

@patch("chimera_intel.core.social_history_monitor.requests.get")
@patch("chimera_intel.core.social_history_monitor.os.path.exists", return_value=True)
@patch("chimera_intel.core.social_history_monitor.os.makedirs")
def test_monitor_profile_changes_detected(mock_makedirs, mock_path_exists, mock_requests_get, mock_bs4_lib, cleanup_db):
    """Tests that changes are detected on the second run."""
    # Arrange
    # Mock the new text
    mock_response = MagicMock(text="<html><body>New Bio Here</body></html>")
    mock_response.raise_for_status.return_value = None
    mock_requests_get.return_value = mock_response
    mock_soup.stripped_strings = ["New", "Bio", "Here"] # Mock parsed text

    # Mock the old text being read from the file
    old_text = "Old Bio Text Here"
    
    target_name = "test_target_changes"
    url = "https.example.com/profile"
    db_file = os.path.join(PROFILE_DB_PATH, f"{target_name}.txt")

    # Act
    # Mock 'open' to read old text and write new text
    m = mock_open(read_data=old_text)
    with patch("builtins.open", m):
        result = monitor_profile_changes(url, target_name)

    # Assert
    m.assert_any_call(db_file, "r", encoding="utf-8") # Read old
    m.assert_any_call(db_file, "w", encoding="utf-8") # Write new
    
    assert result.error is None
    assert result.changes_found is True
    assert "Changes detected" in result.status
    assert "-Old" in result.diff_lines
    assert "-Text" in result.diff_lines
    assert "+New" in result.diff_lines

@patch("chimera_intel.core.social_history_monitor.requests.get")
@patch("chimera_intel.core.social_history_monitor.os.path.exists", return_value=True)
@patch("chimera_intel.core.social_history_monitor.os.makedirs")
def test_monitor_profile_no_changes(mock_makedirs, mock_path_exists, mock_requests_get, mock_bs4_lib, cleanup_db):
    """Tests that no changes are reported if text is identical."""
    # Arrange
    identical_text = "Same Bio Here"
    mock_response = MagicMock(text=f"<html><body>{identical_text}</body></html>")
    mock_response.raise_for_status.return_value = None
    mock_requests_get.return_value = mock_response
    mock_soup.stripped_strings = identical_text.split() # Mock parsed text

    target_name = "test_target_no_change"
    url = "https.example.com/profile"

    # Act
    m = mock_open(read_data=identical_text)
    with patch("builtins.open", m):
        result = monitor_profile_changes(url, target_name)

    # Assert
    assert result.error is None
    assert result.changes_found is False
    assert "No changes detected" in result.status