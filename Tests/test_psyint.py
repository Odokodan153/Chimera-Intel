# Tests/test_psyint.py

import pytest
import json
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, AsyncMock

from chimera_intel.core.psyint import psyint_app, ACTION_NAME
from chimera_intel.core.schemas import ReviewRequest, SyntheticImageResult
from chimera_intel.core.narrative_analyzer import GNewsNarrativeResult

# --- Fixtures ---


@pytest.fixture
def runner():
    """Provides a Typer CliRunner instance."""
    return CliRunner()


@pytest.fixture
def mock_plan_file(tmp_path):
    """Creates a mock campaign_plan.json file."""
    plan_data = {
        "config": {
            "narrative_goal": "Test Goal",
            "base_narrative": "Test Narrative",
            "target_audience_desc": "Test Audience",
            "target_platforms": ["twitter"],
        },
        "narrative_variants": {
            "variant_a": "Test Narrative A",
            "variant_b": "Test Narrative B",
        },
        "identified_audiences": ["audience_1"],
        "synthetic_assets": ["asset_1.jpg"],
    }
    file_path = tmp_path / "test_plan.json"
    with open(file_path, "w") as f:
        json.dump(plan_data, f)
    return str(file_path)


# --- Tests ---


@patch("chimera_intel.core.psyint.generate_swot_from_data", new_callable=AsyncMock)
@patch("chimera_intel.core.psyint.find_target_audiences_by_description", new_callable=AsyncMock)
@patch("chimera_intel.core.psyint.generate_synthetic_image_with_ai", new_callable=AsyncMock)
def test_psyint_plan_command(
    mock_gen_image, mock_find_audiences, mock_gen_swot, runner, tmp_path
):
    """Tests the (low-risk) 'plan' command with real function mocks."""
    # Arrange
    mock_gen_swot.return_value.error = None
    mock_gen_swot.return_value.analysis_text = '{"variant_a": "AI Variant A", "variant_b": "AI Variant B"}'
    
    mock_find_audiences.return_value = ["ai_audience_1"]
    
    # Mock the return of the *real* function, which is a SyntheticImageResult object
    mock_gen_image.return_value = SyntheticImageResult(
        image_url="http://example.com/ai_asset.png",
        prompt="test prompt"
    )
    
    out_file = tmp_path / "plan.json"

    # Act
    result = runner.invoke(
        psyint_app,
        [
            "plan",
            "--goal", "Test Goal",
            "--narrative", "Test Narrative",
            "--audience", "Test Audience",
            "--out", str(out_file),
        ],
        catch_exceptions=False,
    )

    # Assert
    assert result.exit_code == 0
    assert "Campaign plan saved" in result.stdout
    assert out_file.exists()

    with open(out_file, "r") as f:
        data = json.load(f)
    
    assert data["config"]["narrative_goal"] == "Test Goal"
    assert data["narrative_variants"]["variant_a"] == "AI Variant A"
    assert data["identified_audiences"] == ["ai_audience_1"]
    # Check that both calls to the mock image generator were captured
    assert data["synthetic_assets"] == ["http://example.com/ai_asset.png", "http://example.com/ai_asset.png"]


@patch("chimera_intel.core.psyint.track_narrative_gnews")
@patch("chimera_intel.core.psyint.run_pre_flight_checks")
def test_psyint_execute_governance_pass(
    mock_pre_flight, mock_track_narrative, runner, mock_plan_file
):
    """Tests 'execute' when governance checks PASS."""
    # Arrange
    mock_pre_flight.return_value = True  # <-- GOVERNANCE PASS
    
    # Mock the return of the *real* narrative tracker
    mock_track_narrative.return_value = GNewsNarrativeResult(
        query="Test Narrative",
        articles=[{"content": "Monitored article", "source": "Mock", "title": "t", "url": "u", "description": "d"}]
    )
    
    consent_file = "consent.toml" # File just needs to be named

    # Act
    result = runner.invoke(
        psyint_app,
        ["execute", mock_plan_file, "--consent", consent_file],
        catch_exceptions=False,
    )

    # Assert
    assert result.exit_code == 0
    mock_pre_flight.assert_called_with(
        action_name=ACTION_NAME,
        target="Test Audience",
        consent_file=consent_file,
    )
    assert "All pre-flight checks passed" in result.stdout
    assert "SIMULATING CAMPAIGN DEPLOYMENT" in result.stdout
    assert "SIMULATED_EXECUTION" in result.stdout
    # Check that the monitoring simulation ran
    assert '"simulated_hits": 1' in result.stdout


@patch("chimera_intel.core.psyint.HumanReviewService")
@patch("chimera_intel.core.psyint.run_pre_flight_checks")
def test_psyint_execute_governance_fail_and_review(
    mock_pre_flight, mock_review_service, runner, mock_plan_file
):
    """Tests 'execute' when governance checks FAIL and it submits for review."""
    # Arrange
    mock_pre_flight.return_value = False  # <-- GOVERNANCE FAIL
    
    mock_service_instance = MagicMock()
    mock_review_service.return_value = mock_service_instance
    mock_service_instance.submit_for_review.return_value = ReviewRequest(
        id="review-123",
        user="test",
        action_name=ACTION_NAME,
        target="Test Audience"
    )
    
    consent_file = "consent.toml"

    # Act
    result = runner.invoke(
        psyint_app,
        ["execute", mock_plan_file, "--consent", consent_file],
        catch_exceptions=False,
    )

    # Assert
    assert result.exit_code == 0
    mock_pre_flight.assert_called_with(
        action_name=ACTION_NAME,
        target="Test Audience",
        consent_file=consent_file,
    )
    assert "Pre-flight checks FAILED" in result.stdout
    assert "Submitting for human review" in result.stdout
    mock_service_instance.submit_for_review.assert_called_once()
    assert "PENDING_REVIEW" in result.stdout
    assert "review-123" in result.stdout


@patch("chimera_intel.core.psyint.run_pre_flight_checks")
def test_psyint_execute_governance_fail_no_consent(mock_pre_flight, runner, mock_plan_file):
    """
    Tests 'execute' when governance fails (e.g., no consent file provided).
    The underlying governance check will fail, and this should be
    caught and submitted for review.
    """
    # Arrange
    mock_pre_flight.return_value = False  # Governance fails (no consent)
    
    # Patch the review service so it doesn't write to disk
    with patch("chimera_intel.core.psyint.HumanReviewService") as mock_review_service:
        mock_service_instance = MagicMock()
        mock_review_service.return_value = mock_service_instance
        mock_service_instance.submit_for_review.return_value = ReviewRequest(
            id="review-456", user="test", action_name="test", target="test"
        )

        # Act: Run *without* the --consent flag
        result = runner.invoke(
            psyint_app,
            ["execute", mock_plan_file],
            catch_exceptions=False,
        )

        # Assert
        assert result.exit_code == 0
        mock_pre_flight.assert_called_with(
            action_name=ACTION_NAME,
            target="Test Audience",
            consent_file=None,  # Correctly called with None
        )
        assert "Pre-flight checks FAILED" in result.stdout
        assert "PENDING_REVIEW" in result.stdout
        assert "review-456" in result.stdout


def test_psyint_execute_no_plan_file(runner):
    """Tests that 'execute' fails gracefully if the plan file is missing."""
    # Act
    result = runner.invoke(
        psyint_app,
        ["execute", "non_existent_file.json", "--consent", "consent.toml"],
        catch_exceptions=False,
    )

    # Assert
    assert result.exit_code == 1
    assert "Plan file not found" in result.stdout