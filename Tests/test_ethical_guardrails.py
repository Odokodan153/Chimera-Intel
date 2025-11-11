# Tests/test_ethical_guardrails.py

import pytest
from unittest.mock import patch, MagicMock
from chimera_intel.core.ethical_guardrails import (
    EthicalGuardrails,
    DisallowedUseCaseError,
    AllowedUseCase,
    GenerationType,
    RiskLevel,
    SubjectProfile,
    SubjectSensitivity,
    save_subject_profile,
    get_subject_profile_from_db,
    policy_app  # Import the app to test CLI commands
)
from typer.testing import CliRunner

# --- Test Fixtures ---

@pytest.fixture
def guardrails() -> EthicalGuardrails:
    """Provides a fresh instance of the EthicalGuardrails."""
    return EthicalGuardrails()

@pytest.fixture
def runner() -> CliRunner:
    """Provides a Typer CLI runner."""
    return CliRunner()

# --- Mock Data ---
profile_minor = SubjectProfile(
    subject_id="m-1a2b3c",
    display_name="Johnny Minor",
    sensitivity=SubjectSensitivity.MINOR
)
profile_victim = SubjectProfile(
    subject_id="v-9a8b7c",
    display_name="Jane Doe (Victim)",
    sensitivity=SubjectSensitivity.VULNERABLE_PERSON
)
profile_sanctioned = SubjectProfile(
    subject_id="s-7g8h9i",
    display_name="Sanctioned Entity X",
    sensitivity=SubjectSensitivity.SANCTIONED_PERSON
)
profile_official = SubjectProfile(
    subject_id="po-4d5e6f",
    display_name="Senator Adams",
    sensitivity=SubjectSensitivity.PUBLIC_OFFICIAL
)
profile_adult = SubjectProfile(
    subject_id="a-1b2c3d",
    display_name="Consenting CEO",
    sensitivity=SubjectSensitivity.GENERAL_ADULT
)

# --- Test Database Functions ---

@patch("chimera_intel.core.ethical_guardrails.save_scan_to_db")
def test_save_subject_profile(mock_save_scan):
    """Test that saving a profile calls the DB service correctly."""
    save_subject_profile(profile_adult)
    
    mock_save_scan.assert_called_once_with(
        target="consenting ceo", # Should be lowercased
        module="subject_profile",
        data=profile_adult.model_dump(),
        scan_id=profile_adult.subject_id
    )

@patch("chimera_intel.core.ethical_guardrails.get_scans_by_target")
def test_get_subject_profile_from_db_found(mock_get_scans):
    """Test retrieving a profile that exists."""
    mock_get_scans.return_value = [profile_minor.model_dump()]
    
    profile = get_subject_profile_from_db("Johnny Minor")
    
    assert profile == profile_minor
    mock_get_scans.assert_called_once_with(
        target="johnny minor",
        module="subject_profile"
    )

@patch("chimera_intel.core.ethical_guardrails.get_scans_by_target")
def test_get_subject_profile_from_db_not_found(mock_get_scans):
    """Test retrieving a profile that does not exist."""
    mock_get_scans.return_value = []
    
    profile = get_subject_profile_from_db("Unknown Person")
    
    assert profile is None
    mock_get_scans.assert_called_once_with(
        target="unknown person",
        module="subject_profile"
    )

# --- Test Policy Logic (Blocked Cases) ---

@patch("chimera_intel.core.ethical_guardrails.get_scans_by_target")
def test_blocked_minor(mock_get_scans, guardrails):
    mock_get_scans.return_value = [profile_minor.model_dump()]
    with pytest.raises(DisallowedUseCaseError, match="minors is strictly prohibited"):
        guardrails.check_synthetic_media_policy(
            use_case=AllowedUseCase.MARKETING,
            generation_type=GenerationType.VOICE_CLONE,
            subject_name="Johnny Minor"
        )

@patch("chimera_intel.core.ethical_guardrails.get_scans_by_target")
def test_blocked_victim(mock_get_scans, guardrails):
    mock_get_scans.return_value = [profile_victim.model_dump()]
    with pytest.raises(DisallowedUseCaseError, match="victims of crimes is strictly prohibited"):
        guardrails.check_synthetic_media_policy(
            use_case=AllowedUseCase.FILM_ADVERTISING,
            generation_type=GenerationType.FACE_REENACTMENT,
            subject_name="Jane Doe (Victim)"
        )

# --- Test Policy Logic (Allowed Cases) ---

@patch("chimera_intel.core.ethical_guardrails.get_scans_by_target")
def test_allowed_unknown_adult_marketing(mock_get_scans, guardrails):
    """An unknown name defaults to GENERAL_ADULT and is allowed."""
    mock_get_scans.return_value = [] # Not found in DB
    
    assert guardrails.check_synthetic_media_policy(
        use_case=AllowedUseCase.MARKETING,
        generation_type=GenerationType.FACE_REENACTMENT,
        subject_name="Some New Person"
    )
    mock_get_scans.assert_called_once_with(target="some new person", module="subject_profile")

@patch("chimera_intel.core.ethical_guardrails.get_scans_by_target")
def test_allowed_stock_person_no_name(mock_get_scans, guardrails):
    """Fully synthetic generation without a name is allowed."""
    assert guardrails.check_synthetic_media_policy(
        use_case=AllowedUseCase.SYNTHETIC_SPOKESPERSON,
        generation_type=GenerationType.FULLY_SYNTHETIC_FACE,
        subject_name=None
    )
    # get_scans_by_target should not be called if name is None
    mock_get_scans.assert_not_called()

# --- Test Risk Level Logic ---

@patch("chimera_intel.core.ethical_guardrails.get_scans_by_target")
def test_risk_level_low(mock_get_scans, guardrails):
    mock_get_scans.return_value = [] # Not found, defaults to stock
    risk = guardrails.determine_risk_level(
        use_case=AllowedUseCase.SYNTHETIC_SPOKESPERSON,
        subject_name="Stock Person"
    )
    assert risk == RiskLevel.LOW

@patch("chimera_intel.core.ethical_guardrails.get_scans_by_target")
def test_risk_level_medium(mock_get_scans, guardrails):
    mock_get_scans.return_value = [profile_adult.model_dump()]
    risk = guardrails.determine_risk_level(
        use_case=AllowedUseCase.MARKETING,
        subject_name="Consenting CEO"
    )
    assert risk == RiskLevel.MEDIUM

@patch("chimera_intel.core.ethical_guardrails.get_scans_by_target")
def test_risk_level_high_official(mock_get_scans, guardrails):
    mock_get_scans.return_value = [profile_official.model_dump()]
    risk = guardrails.determine_risk_level(
        use_case=AllowedUseCase.FILM_ADVERTISING,
        subject_name="Senator Adams"
    )
    assert risk == RiskLevel.HIGH

# --- Test CLI Commands ---

@patch("chimera_intel.core.ethical_guardrails.save_subject_profile")
def test_cli_add_subject(mock_save_profile, runner):
    """Test the 'add-subject' CLI command."""
    result = runner.invoke(
        policy_app,
        [
            "add-subject",
            "--name", "Senator Adams",
            "--sensitivity", "public_official_sensitive_role",
            "--notes", "Test note"
        ]
    )
    assert result.exit_code == 0
    assert "Successfully saved subject profile" in result.stdout
    assert "Senator Adams" in result.stdout
    assert "public_official_sensitive_role" in result.stdout
    
    # Check that the DB function was called with the correct data
    mock_save_profile.assert_called_once()
    saved_profile = mock_save_profile.call_args[0][0]
    assert isinstance(saved_profile, SubjectProfile)
    assert saved_profile.display_name == "Senator Adams"
    assert saved_profile.sensitivity == SubjectSensitivity.PUBLIC_OFFICIAL

@patch("chimera_intel.core.ethical_guardrails.get_scans_by_target")
def test_cli_check_policy_passed(mock_get_scans, runner):
    """Test the 'check' CLI command for a passing case."""
    mock_get_scans.return_value = [profile_adult.model_dump()] # "Consenting CEO"
    
    result = runner.invoke(
        policy_app,
        [
            "check",
            "--use-case", "marketing_assets_with_consent",
            "--gen-type", "voice_clone",
            "--subject-name", "Consenting CEO"
        ]
    )
    assert result.exit_code == 0
    assert "Policy Check PASSED" in result.stdout

@patch("chimera_intel.core.ethical_guardrails.get_scans_by_target")
def test_cli_check_policy_failed(mock_get_scans, runner):
    """Test the 'check' CLI command for a failing case."""
    mock_get_scans.return_value = [profile_minor.model_dump()] # "Johnny Minor"
    
    result = runner.invoke(
        policy_app,
        [
            "check",
            "--use-case", "marketing_assets_with_consent",
            "--gen-type", "voice_clone",
            "--subject-name", "Johnny Minor"
        ]
    )
    assert result.exit_code == 0 # CLI commands exit gracefully
    assert "Policy Check FAILED" in result.stdout
    assert "minors is strictly prohibited" in result.stdout

@patch("chimera_intel.core.ethical_guardrails.get_scans_by_target")
def test_cli_get_risk_high(mock_get_scans, runner):
    """Test the 'get-risk' CLI command for a high-risk case."""
    mock_get_scans.return_value = [profile_official.model_dump()] # "Senator Adams"
    
    result = runner.invoke(
        policy_app,
        [
            "get-risk",
            "--use-case", "film_advertising_with_rights",
            "--subject-name", "Senator Adams"
        ]
    )
    assert result.exit_code == 0
    assert "Determined Risk Level: HIGH" in result.stdout
    assert "Dual approval + senior review" in result.stdout