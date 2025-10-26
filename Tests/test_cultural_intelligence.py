import pytest
from unittest.mock import patch, MagicMock
from chimera_intel.core import cultural_intelligence

# A fixture to automatically clear the cache before each test
@pytest.fixture(autouse=True)
def clear_cache_fixture():
    """Ensures the global cache is empty before each test."""
    cultural_intelligence._profile_cache.clear()
    yield
    cultural_intelligence._profile_cache.clear()

@pytest.fixture
def mock_db(mocker):
    """Mocks the database connection and cursor."""
    mock_cursor = MagicMock()
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mocker.patch(
        "chimera_intel.core.cultural_intelligence.get_db_connection",
        return_value=mock_conn
    )
    return mock_conn, mock_cursor

@pytest.fixture
def mock_db_no_conn(mocker):
    """Mocks the database connection returning None."""
    mocker.patch(
        "chimera_intel.core.cultural_intelligence.get_db_connection",
        return_value=None
    )

@pytest.fixture
def mock_console(mocker):
    """Mocks the console object to prevent printing during tests."""
    return mocker.patch("chimera_intel.core.cultural_intelligence.console")


# --- Test add_cultural_profile ---

def test_add_cultural_profile_success(mock_db, mock_console):
    """Tests adding a new profile successfully."""
    mock_conn, mock_cursor = mock_db
    
    # Pre-populate cache to ensure it gets cleared
    cultural_intelligence._profile_cache["US"] = {"country_name": "Old Data"}
    
    profile_data = {
        "country_code": "US", "country_name": "United States", "directness": 9,
        "formality": 4, "power_distance": 40, "individualism": 91, "uncertainty_avoidance": 46,
    }
    
    cultural_intelligence.add_cultural_profile(profile_data)
    
    # Check that execute and commit were called
    mock_cursor.execute.assert_called_once()
    assert "INSERT INTO cultural_profiles" in mock_cursor.execute.call_args[0][0]
    assert "ON CONFLICT (country_code) DO UPDATE" in mock_cursor.execute.call_args[0][0]
    assert mock_cursor.execute.call_args[0][1][0] == "US" # Check data
    mock_conn.commit.assert_called_once()
    
    # Check that success was printed
    mock_console.print.assert_called_with(
        "[bold green]Successfully added/updated cultural profile for United States.[/bold green]"
    )
    
    # Check that the cache was cleared
    assert "US" not in cultural_intelligence._profile_cache

def test_add_cultural_profile_db_connection_fails(mock_db_no_conn, mock_console, caplog):
    """Tests function behavior when DB connection is None."""
    profile_data = {"country_code": "US", "country_name": "United States", "directness": 9,
        "formality": 4, "power_distance": 40, "individualism": 91, "uncertainty_avoidance": 46}
    
    with caplog.at_level("ERROR"):
        cultural_intelligence.add_cultural_profile(profile_data)
        
    # Check that an error was logged
    assert "Cannot add cultural profile: No database connection." in caplog.text
    
    # Check that no console messages were printed
    mock_console.print.assert_not_called()

def test_add_cultural_profile_db_exception(mock_db, mock_console):
    """Tests a database exception during execution."""
    mock_conn, mock_cursor = mock_db
    mock_cursor.execute.side_effect = Exception("Test DB Error")
    
    profile_data = {
        "country_code": "US", "country_name": "United States", "directness": 9,
        "formality": 4, "power_distance": 40, "individualism": 91, "uncertainty_avoidance": 46,
    }
    
    cultural_intelligence.add_cultural_profile(profile_data)
    
    # Check that commit was not called
    mock_conn.commit.assert_not_called()
    
    # Check that error was printed
    mock_console.print.assert_called_with(
        "[bold red]Database Error:[/bold red] Could not add cultural profile: Test DB Error"
    )
    
    # Check that connection is closed
    mock_conn.close.assert_called_once()


# --- Test get_cultural_profile ---

def test_get_cultural_profile_from_db(mock_db):
    """Tests retrieving a profile from the DB (cache miss)."""
    mock_conn, mock_cursor = mock_db
    db_record = ("US", "United States", 9, 4, 40, 91, 46)
    mock_cursor.fetchone.return_value = db_record
    
    profile = cultural_intelligence.get_cultural_profile("US")
    
    # Check that DB was queried
    mock_cursor.execute.assert_called_once_with(
        "SELECT country_code, country_name, directness, formality, power_distance, individualism, uncertainty_avoidance FROM cultural_profiles WHERE country_code = %s",
        ("US",)
    )
    
    # Check that the returned profile is correct
    assert profile is not None
    assert profile["country_code"] == "US"
    assert profile["country_name"] == "United States"
    assert profile["individualism"] == 91
    
    # Check that the profile was added to the cache
    assert "US" in cultural_intelligence._profile_cache
    assert cultural_intelligence._profile_cache["US"] == profile
    
    # Check that connection is closed
    mock_conn.close.assert_called_once()

def test_get_cultural_profile_from_cache(mock_db):
    """Tests retrieving a profile from the cache (cache hit)."""
    mock_conn, mock_cursor = mock_db
    cached_profile = {"country_code": "US", "country_name": "Cached Data"}
    cultural_intelligence._profile_cache["US"] = cached_profile
    
    profile = cultural_intelligence.get_cultural_profile("US")
    
    # Check that the DB was NOT queried
    mock_cursor.execute.assert_not_called()
    mock_conn.close.assert_not_called() # Connection shouldn't even be opened
    
    # Check that the cached profile was returned
    assert profile == cached_profile

def test_get_cultural_profile_not_found(mock_db):
    """Tests getting a profile that does not exist."""
    mock_conn, mock_cursor = mock_db
    mock_cursor.fetchone.return_value = None # No record found
    
    profile = cultural_intelligence.get_cultural_profile("XX")
    
    # Check that DB was queried
    mock_cursor.execute.assert_called_once_with(
        "SELECT country_code, country_name, directness, formality, power_distance, individualism, uncertainty_avoidance FROM cultural_profiles WHERE country_code = %s",
        ("XX",)
    )
    
    # Check that result is None
    assert profile is None
    
    # Check that nothing was added to the cache
    assert "XX" not in cultural_intelligence._profile_cache

def test_get_cultural_profile_empty_code(mock_db):
    """Tests calling with None or empty string."""
    mock_conn, mock_cursor = mock_db
    
    assert cultural_intelligence.get_cultural_profile(None) is None
    assert cultural_intelligence.get_cultural_profile("") is None
    
    # Check that DB was NOT queried
    mock_cursor.execute.assert_not_called()

def test_get_cultural_profile_db_connection_fails(mock_db_no_conn, caplog):
    """Tests behavior when DB connection is None."""
    with caplog.at_level("ERROR"):
        profile = cultural_intelligence.get_cultural_profile("US")
        
    assert profile is None
    assert "Cannot retrieve cultural profile: No database connection." in caplog.text

def test_get_cultural_profile_db_exception(mock_db, mock_console):
    """Tests a database exception during retrieval."""
    mock_conn, mock_cursor = mock_db
    mock_cursor.execute.side_effect = Exception("Test DB Read Error")
    
    profile = cultural_intelligence.get_cultural_profile("US")
    
    assert profile is None
    mock_console.print.assert_called_with(
        "[bold red]Database Error:[/bold red] Could not retrieve cultural profile: Test DB Read Error"
    )
    mock_conn.close.assert_called_once()


# --- Test get_all_cultural_profiles ---

def test_get_all_cultural_profiles_success(mock_db):
    """Tests retrieving all profiles successfully."""
    mock_conn, mock_cursor = mock_db
    db_records = [
        ("DE", "Germany", 8, 7, 35, 67, 65),
        ("JP", "Japan", 3, 8, 54, 46, 92),
    ]
    mock_cursor.fetchall.return_value = db_records
    
    profiles = cultural_intelligence.get_all_cultural_profiles()
    
    # Check that DB was queried
    mock_cursor.execute.assert_called_once_with(
        "SELECT country_code, country_name, directness, formality, power_distance, individualism, uncertainty_avoidance FROM cultural_profiles ORDER BY country_name;"
    )
    
    # Check results
    assert len(profiles) == 2
    assert profiles[0]["country_code"] == "DE"
    assert profiles[1]["country_name"] == "Japan"
    mock_conn.close.assert_called_once()

def test_get_all_cultural_profiles_no_data(mock_db):
    """Tests retrieving when no profiles are in the DB."""
    mock_conn, mock_cursor = mock_db
    mock_cursor.fetchall.return_value = [] # No records
    
    profiles = cultural_intelligence.get_all_cultural_profiles()
    
    assert profiles == []
    mock_conn.close.assert_called_once()

def test_get_all_cultural_profiles_db_connection_fails(mock_db_no_conn, caplog):
    """Tests behavior when DB connection is None."""
    with caplog.at_level("ERROR"):
        profiles = cultural_intelligence.get_all_cultural_profiles()
        
    assert profiles == []
    assert "Cannot retrieve cultural profiles: No database connection." in caplog.text

def test_get_all_cultural_profiles_db_exception(mock_db, mock_console):
    """Tests a database exception during retrieval."""
    mock_conn, mock_cursor = mock_db
    mock_cursor.execute.side_effect = Exception("Test DB ReadAll Error")
    
    profiles = cultural_intelligence.get_all_cultural_profiles()
    
    assert profiles == []
    mock_console.print.assert_called_with(
        "[bold red]Database Error:[/bold red] Could not retrieve all cultural profiles: Test DB ReadAll Error"
    )
    mock_conn.close.assert_called_once()

# --- Test populate_initial_cultural_data ---

@patch("chimera_intel.core.cultural_intelligence.add_cultural_profile")
def test_populate_initial_cultural_data(mock_add_profile, mock_console):
    """Tests that the populate function calls add_cultural_profile for each item."""
    cultural_intelligence.populate_initial_cultural_data()
    
    # Check that it was called for all initial profiles (4 in the source file)
    assert mock_add_profile.call_count == 4
    
    # Check the data for one of the calls
    first_call_args = mock_add_profile.call_args_list[0][0][0]
    assert first_call_args["country_code"] == "US"
    assert first_call_args["country_name"] == "United States"
    
    # Check that the status message was printed
    mock_console.print.assert_called_with("[yellow]Populating initial cultural data...[/yellow]")