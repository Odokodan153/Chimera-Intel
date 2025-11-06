import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from chimera_intel.core.action_governance import gov_app, run_pre_flight_checks
from chimera_intel.core.schemas import SanctionsScreeningResult

runner = CliRunner()

@pytest.fixture
def mock_legint():
    """Mocks legint and security_utils functions."""
    with patch("chimera_intel.core.action_governance.screen_for_sanctions") as mock_sanctions, \
         patch("chimera_intel.core.action_governance.load_consent") as mock_load, \
         patch("chimera_intel.core.action_governance.check_consent_for_action") as mock_check:
        
        # Default: Target is NOT sanctioned
        mock_sanctions.return_value = SanctionsScreeningResult(query="TestCorp", hits_found=0)
        
        # Default: Consent is valid
        mock_load.return_value = {"id": "consent-123"}
        mock_check.return_value = True
        
        yield mock_sanctions, mock_load, mock_check

def test_run_pre_flight_checks_passive(mock_legint):
    """Tests that a benign action passes all checks."""
    mock_sanctions, _, _ = mock_legint
    action_name = "legint:sanctions-screener"
    target = "SafeCorp"
    
    # Test a benign action
    is_allowed = run_pre_flight_checks(action_name, target, None)
    
    assert is_allowed is True
    # Sanctions check should still run
    mock_sanctions.assert_called_with("SafeCorp")

def test_run_pre_flight_checks_disallowed(mock_legint):
    """Tests that a disallowed action is blocked immediately."""
    mock_sanctions, _, _ = mock_legint
    action_name = "example:disallowed"
    target = "AnyCorp"
    
    is_allowed = run_pre_flight_checks(action_name, target, None)
    
    assert is_allowed is False
    # Compliance checks should NOT run if action is disallowed
    mock_sanctions.assert_not_called()

def test_run_pre_flight_checks_aggressive_no_consent(mock_legint):
    """Tests that an aggressive action is blocked without a consent file."""
    action_name = "red-team:generate"
    target = "TestCorp"
    
    is_allowed = run_pre_flight_checks(action_name, target, consent_file=None)
    
    assert is_allowed is False

def test_run_pre_flight_checks_aggressive_with_consent(mock_legint):
    """Tests that an aggressive action passes with valid consent."""
    mock_sanctions, _, mock_check = mock_legint
    action_name = "red-team:generate"
    target = "TestCorp"
    consent_file = "consent.yaml"
    
    mock_check.return_value = True # Consent check passes
    mock_sanctions.return_value = SanctionsScreeningResult(query="TestCorp", hits_found=0) # Sanctions check passes
    
    is_allowed = run_pre_flight_checks(action_name, target, consent_file)
    
    assert is_allowed is True
    mock_check.assert_called_with({"id": "consent-123"}, "TestCorp", "generate")

def test_run_pre_flight_checks_aggressive_invalid_consent(mock_legint):
    """Tests that an aggressive action is blocked by invalid consent."""
    _, _, mock_check = mock_legint
    action_name = "red-team:generate"
    target = "TestCorp"
    consent_file = "consent.yaml"
    
    mock_check.return_value = False # Consent check fails
    
    is_allowed = run_pre_flight_checks(action_name, target, consent_file)
    
    assert is_allowed is False

def test_run_pre_flight_checks_sanctions_block(mock_legint):
    """Tests that any action (even benign) is blocked if target is sanctioned."""
    mock_sanctions, _, _ = mock_legint
    action_name = "recon:domain-scan"
    target = "SanctionedCorp"

    # Setup mock to return a sanctions hit
    mock_sanctions.return_value = SanctionsScreeningResult(query="SanctionedCorp", hits_found=1, entities=[MagicMock()])
    
    is_allowed = run_pre_flight_checks(action_name, target, None)
    
    assert is_allowed is False
    mock_sanctions.assert_called_with("SanctionedCorp")

def test_cli_check_pass(mock_legint):
    """Tests the CLI 'check' command for a passing case."""
    result = runner.invoke(gov_app, ["check", "recon:domain-scan", "SafeCorp"])
    assert result.exit_code == 0
    assert "All pre-flight checks passed" in result.stdout
    assert "Action would be allowed" in result.stdout

def test_cli_check_fail(mock_legint):
    """Tests the CLI 'check' command for a failing (disallowed) case."""
    result = runner.invoke(gov_app, ["check", "example:disallowed", "AnyCorp"])
    assert result.exit_code == 1
    assert "ACTION BLOCKED" in result.stdout
    assert "This action is classified as 'Disallowed'" in result.stdout

def test_cli_list(mock_legint):
    """Tests the CLI 'list' command."""
    result = runner.invoke(gov_app, ["list"])
    assert result.exit_code == 0
    assert "recon:domain-scan" in result.stdout
    assert "(Aggressive)" in result.stdout