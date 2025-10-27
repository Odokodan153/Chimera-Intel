from typer.testing import CliRunner
import httpx
from unittest.mock import patch, MagicMock
from time import sleep
from threading import Lock
import os
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.io_tracking import FileChange, IOTracking, FileChangeType

# Patch the API key *before* importing the io_tracking_app.
# This ensures the Typer app initializes correctly at import time,
# resolving the exit code 2 errors.
with patch.object(API_KEYS, "gnews_api_key", "fake_key_for_import"):
    from chimera_intel.core.io_tracking import io_tracking_app
# --- END FIX ---

runner = CliRunner()


@patch("chimera_intel.core.io_tracking.search_reddit_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_twitter_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_news_narrative")
def test_track_influence_success(
    mock_search_news, mock_search_twitter, mock_search_reddit
):
    """
    Tests the track-influence command with a successful API response.
    """
    # Arrange

    mock_search_news.return_value = [
        {
            "title": "Rumors of Failure Swirl Around New Product",
            "source": {"name": "Tech News Today"},
            "url": "http://example.com/news1",
        },
        {
            "title": "Product Failure Claims Debunked by Company",
            "source": {"name": "Business Insider"},
            "url": "http://example.com/news2",
        },
    ]

    # Act
    # --- FIX: Removed the "track" command name from the invoke call ---
    result = runner.invoke(
        io_tracking_app, ["--narrative", "rumors of product failure"]
    )
    # --- End Fix ---

    # Assert

    assert result.exit_code == 0
    assert (
        "Tracking influence campaign for narrative: 'rumors of product failure'"
        in result.output
    )
    assert "Found 2 news articles related to the narrative." in result.output
    assert "Tech News Today" in result.output
    assert "Business Insider" in result.output


# --- FIX APPLIED: Added mocks for twitter and reddit ---
@patch("chimera_intel.core.io_tracking.search_reddit_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_twitter_narrative", return_value=[])
def test_track_influence_no_api_key(mock_search_twitter, mock_search_reddit):
# --- END FIX ---
    """
    Tests the track-influence command when the API key is missing.
    """
    # Arrange
    # We patch the key to None *within* this test's context
    # to override the global 'fake_key_for_import' and test the error case.
    with patch("chimera_intel.core.io_tracking.API_KEYS.gnews_api_key", None):
        # Act
        # --- FIX: Removed the "track" command name from the invoke call ---
        result = runner.invoke(
            io_tracking_app, ["--narrative", "some narrative"]
        )
        # --- End Fix ---

    # Assert

    assert result.exit_code == 1
    assert "Configuration Error: GNEWS_API_KEY not found in .env file." in result.output


# --- FIX APPLIED: Added mocks for twitter and reddit ---
@patch("chimera_intel.core.io_tracking.search_reddit_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_twitter_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_news_narrative")
def test_track_influence_api_error(
    mock_search_news, mock_search_twitter, mock_search_reddit
):
# --- END FIX ---
    """
    Tests the track-influence command when the GNews API returns an error.
    """
    # Arrange
    # The API key is already set by the import-level patch,
    # so we only need to mock the side effect.
    mock_search_news.side_effect = httpx.HTTPStatusError(
        "API Error", request=MagicMock(), response=httpx.Response(500)
    )

    # Act
    # --- FIX: Removed the "track" command name from the invoke call ---
    result = runner.invoke(io_tracking_app, ["--narrative", "api failure"])
    # --- End Fix ---

    # Assert

    assert result.exit_code == 1
    assert "API Error: Failed to fetch data. Status code: 500" in result.output
# --- Original Tests (for context, unchanged) ---

def test_file_change_model():
    """Tests the FileChange pydantic model."""
    change = FileChange(
        change_type=FileChangeType.MODIFIED,
        file_path="/tmp/test.txt",
        message="File was modified.",
    )
    assert change.change_type == FileChangeType.MODIFIED
    assert change.file_path == "/tmp/test.txt"


def test_io_tracking_initialization():
    """Tests the IOTracking class initializes correctly."""
    tracker = IOTracking()
    assert tracker.file_paths == set()
    assert tracker.file_states == {}
    assert isinstance(tracker.lock, Lock)


def test_add_and_remove_file(tmp_path):
    """Tests adding and removing a file from the tracker."""
    tracker = IOTracking()
    test_file = tmp_path / "test.txt"
    test_file.write_text("initial content")

    # Test Add
    tracker.add_file(str(test_file))
    assert str(test_file) in tracker.file_paths
    assert str(test_file) in tracker.file_states
    assert tracker.file_states[str(test_file)] is not None

    # Test Remove
    tracker.remove_file(str(test_file))
    assert str(test_file) not in tracker.file_paths
    assert str(test_file) not in tracker.file_states


def test_check_files_no_changes(tmp_path):
    """Tests that check_files yields no changes if files are untouched."""
    tracker = IOTracking()
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    tracker.add_file(str(test_file))

    # First check (initializes state)
    list(tracker.check_files())
    
    # Second check (no changes)
    changes = list(tracker.check_files())
    assert len(changes) == 0


def test_check_files_modification(tmp_path):
    """Tests detection of file modification."""
    tracker = IOTracking()
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    tracker.add_file(str(test_file))

    # Initial check
    list(tracker.check_files())
    
    # Modify file (ensure mtime changes)
    sleep(0.01)
    test_file.write_text("new content")
    
    changes = list(tracker.check_files())
    assert len(changes) == 1
    assert changes[0].change_type == FileChangeType.MODIFIED
    assert changes[0].file_path == str(test_file)


def test_check_files_creation(tmp_path):
    """Tests detection of file creation (for a file added while it didn't exist)."""
    tracker = IOTracking()
    test_file = tmp_path / "test_new.txt"
    
    # Add file to tracker *before* it exists
    tracker.add_file(str(test_file))
    
    # First check, file doesn't exist, state is None
    changes_init = list(tracker.check_files())
    assert len(changes_init) == 0
    assert tracker.file_states[str(test_file)] is None

    # Create the file
    test_file.write_text("I exist now")
    
    # Second check, should detect creation
    changes_created = list(tracker.check_files())
    assert len(changes_created) == 1
    assert changes_created[0].change_type == FileChangeType.CREATED
    assert changes_created[0].file_path == str(test_file)


def test_check_files_deletion(tmp_path):
    """Tests detection of file deletion."""
    tracker = IOTracking()
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    tracker.add_file(str(test_file))

    # Initial check
    list(tracker.check_files())
    
    # Delete file
    os.remove(str(test_file))
    
    changes = list(tracker.check_files())
    assert len(changes) == 1
    assert changes[0].change_type == FileChangeType.DELETED
    assert changes[0].file_path == str(test_file)


# --- NEW EXTENDED TESTS ---

@patch("chimera_intel.core.io_tracking.os.path.getmtime", return_value=12345.0)
@patch("chimera_intel.core.io_tracking.os.path.getsize", return_value=100)
def test_get_file_state_success(mock_getsize, mock_getmtime, tmp_path):
    """Tests the internal _get_file_state method on success."""
    tracker = IOTracking()
    test_file = tmp_path / "test.txt"
    
    state = tracker._get_file_state(str(test_file))
    
    assert state == (12345.0, 100)
    mock_getmtime.assert_called_with(str(test_file))
    mock_getsize.assert_called_with(str(test_file))


@patch("chimera_intel.core.io_tracking.os.path.getmtime", side_effect=FileNotFoundError)
def test_get_file_state_file_not_found(mock_getmtime, tmp_path):
    """Tests the internal _get_file_state method when the file doesn't exist."""
    tracker = IOTracking()
    test_file = tmp_path / "non_existent.txt"
    
    state = tracker._get_file_state(str(test_file))
    
    assert state is None
    mock_getmtime.assert_called_with(str(test_file))


def test_remove_non_existent_file():
    """Tests that removing a file that isn't tracked doesn't raise an error."""
    tracker = IOTracking()
    tracker.add_file("file1.txt")
    
    # Should not raise any exception
    tracker.remove_file("non_existent.txt")
    
    assert "non_existent.txt" not in tracker.file_paths
    assert "non_existent.txt" not in tracker.file_states
    assert "file1.txt" in tracker.file_paths


def test_add_duplicate_file(tmp_path):
    """Tests that adding a file twice updates its state."""
    tracker = IOTracking()
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    
    tracker.add_file(str(test_file))
    initial_state = tracker.file_states[str(test_file)]
    assert initial_state is not None
    
    # Modify file
    sleep(0.01)
    test_file.write_text("new content")
    
    # Add the same file again
    tracker.add_file(str(test_file))
    new_state = tracker.file_states[str(test_file)]
    
    assert new_state is not None
    assert new_state != initial_state


def test_check_files_state_transitions(tmp_path):
    """Tests multiple state transitions in a row: CREATED -> MODIFIED -> DELETED."""
    tracker = IOTracking()
    test_file = tmp_path / "state_test.txt"

    # 1. Add to tracker (file doesn't exist)
    tracker.add_file(str(test_file))
    list(tracker.check_files()) # Initial state: None
    
    # 2. Create file
    sleep(0.01)
    test_file.write_text("created")
    
    changes_created = list(tracker.check_files())
    assert len(changes_created) == 1
    assert changes_created[0].change_type == FileChangeType.CREATED
    created_state = tracker.file_states[str(test_file)]
    
    # 3. Modify file
    sleep(0.01)
    test_file.write_text("modified")
    
    changes_modified = list(tracker.check_files())
    assert len(changes_modified) == 1
    assert changes_modified[0].change_type == FileChangeType.MODIFIED
    modified_state = tracker.file_states[str(test_file)]
    assert modified_state != created_state

    # 4. Delete file
    sleep(0.01)
    os.remove(str(test_file))
    
    changes_deleted = list(tracker.check_files())
    assert len(changes_deleted) == 1
    assert changes_deleted[0].change_type == FileChangeType.DELETED
    assert tracker.file_states[str(test_file)] is None