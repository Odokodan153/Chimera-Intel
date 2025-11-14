import pytest
import asyncio
import json
from unittest.mock import patch, MagicMock, AsyncMock

from typer.testing import CliRunner
from chimera_intel.core.key_personnel_tracker import (
    key_personnel_app,
    track_individual,
    KeyPersonnelInput,
)
from chimera_intel.core.schemas import AIFeatureResult
from chimera_intel.core.google_search import GoogleSearchResult, GoogleSearchItem

# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio

# Mock API_KEYS
@pytest.fixture(autouse=True)
def mock_api_keys():
    with patch("chimera_intel.core.key_personnel_tracker.API_KEYS") as mock_keys:
        mock_keys.google_api_key = "test_google_key"
        mock_keys.google_cse_id = "test_cse_id"
        yield mock_keys

# Mock dependent modules
@pytest.fixture
def mock_dependencies():
    with patch(
        "chimera_intel.core.key_personnel_tracker.search_google",
        new_callable=AsyncMock,
    ) as mock_search, patch(
        "chimera_intel.core.key_personnel_tracker.generate_swot_from_data"
    ) as mock_ai, patch(
        "chimera_intel.core.key_personnel_tracker.save_or_print_results"
    ) as mock_save, patch(
        "chimera_intel.core.key_personnel_tracker.save_scan_to_db"
    ) as mock_db, patch(
        "chimera_intel.core.key_personnel_tracker.resolve_target"
    ) as mock_resolve:
        
        mock_resolve.return_value = "TestCo"
        
        yield {
            "search": mock_search,
            "ai": mock_ai,
            "save": mock_save,
            "db": mock_db,
            "resolve": mock_resolve,
        }


async def test_track_individual(mock_dependencies):
    person = KeyPersonnelInput(
        full_name="Jane Doe",
        title="VP of Engineering"
    )
    
    # Mock return values for search_google
    mock_linkedin_result = GoogleSearchResult(
        items=[
            GoogleSearchItem(
                title="Jane Doe - VP of AI - TestCo",
                link="https://linkedin.com/in/janedoe",
                snippet="Jane Doe, VP of AI at TestCo. Formerly VP of Engineering."
            )
        ]
    )
    mock_news_result = GoogleSearchResult(
        items=[
            GoogleSearchItem(
                title="TestCo poaches Jane Doe",
                link="https://news.com/janedoe",
                snippet="TestCo announced the hiring of Jane Doe as its new VP of AI."
            )
        ]
    )
    mock_conf_result = GoogleSearchResult(items=[]) # No conference results

    mock_dependencies["search"].side_effect = [
        mock_linkedin_result,
        mock_news_result,
        mock_conf_result,
    ]

    result = await track_individual(
        person, "TestCo", "test_google_key", "test_cse_id"
    )

    assert result.input_data.full_name == "Jane Doe"
    assert result.current_title == "Jane Doe - VP of AI - TestCo"
    assert len(result.findings) == 2
    
    assert result.findings[0].source == "LinkedIn (Google)"
    assert "VP of AI" in result.findings[0].summary
    # It detected a change from her input title "VP of Engineering"
    assert result.findings[0].finding_type == "JobChange"
    
    assert result.findings[1].source == "News"
    assert "hiring of Jane Doe" in result.findings[1].summary
    assert result.findings[1].finding_type == "Mention"


def test_run_personnel_tracking_cli(mock_dependencies):
    runner = CliRunner()
    
    # Mock the JSON file
    mock_personnel_list = [
        {"full_name": "Jane Doe", "title": "VP of Engineering"},
        {"full_name": "John Smith", "title": "Lead Engineer"}
    ]
    mock_json_content = json.dumps(mock_personnel_list)
    
    # Mock AI response
    mock_dependencies["ai"].return_value = AIFeatureResult(
        analysis_text="**Strategic Shift**: Jane Doe hired as VP of AI, signaling a new focus."
    )
    
    # Mock search_google to return empty results to avoid complex async mocking in CLI test
    mock_dependencies["search"].return_value = GoogleSearchResult(items=[])

    with runner.isolated_filesystem():
        with open("people.json", "w") as f:
            f.write(mock_json_content)

        result = runner.invoke(
            key_personnel_app,
            ["track", "--file", "people.json", "--company", "TestCo"],
            catch_exceptions=False,
        )

    assert result.exit_code == 0
    assert "Tracking 2 key personnel for TestCo" in result.stdout
    assert "Strategic Analysis:" in result.stdout
    assert "signaling a new focus" in result.stdout

    # Verify save was called
    mock_dependencies["save"].assert_called_once()
    saved_data = mock_dependencies["save"].call_args[0][0]
    assert saved_data["company_name"] == "TestCo"
    assert "signaling a new focus" in saved_data["strategic_analysis"]
    assert len(saved_data["tracked_profiles"]) == 2

    # Verify DB save was called
    mock_dependencies["db"].assert_called_once()
    db_data = mock_dependencies["db"].call_args[1]["data"]
    assert db_data["company_name"] == "TestCo"