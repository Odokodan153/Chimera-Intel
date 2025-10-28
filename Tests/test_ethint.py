import pytest
import json
from unittest.mock import patch, MagicMock, mock_open
from typer.testing import CliRunner

from chimera_intel.core.schemas import Operation, Target
from chimera_intel.core.ethint import (
    audit_operation,
    load_frameworks,
    app as ethint_app,
)
# --- FIX: Import the module to reset its cache ---
import chimera_intel.core.ethint

# --- Fixtures ---

@pytest.fixture
def runner():
    """Provides a Typer CliRunner instance."""
    return CliRunner()

# FIX: Removed the autouse logging disable fixture.
# This fixture was preventing caplog from capturing log messages,
# causing all the test_load_frameworks_* tests to fail.
# @pytest.fixture(autouse=True)
# def disable_logging():
#     """Disable logging output during tests for a cleaner test run."""
#     logging.disable(logging.CRITICAL)
#     yield
#     logging.disable(logging.NOTSET)

# --- FIX: Add fixture to reset the stateful cache before each test ---
@pytest.fixture(autouse=True)
def reset_ethint_cache():
    """Resets the global framework cache before each test."""
    chimera_intel.core.ethint._ETHICAL_FRAMEWORKS_CACHE = None
    yield
    chimera_intel.core.ethint._ETHICAL_FRAMEWORKS_CACHE = None
# --- End Fix ---

@pytest.fixture
def mock_frameworks_dict():
    """Provides a mock dictionary of ethical frameworks."""
    return {
        "data_privacy_gdpr": {
            "version": "1.0",
            "rules": [
                {"rule_id": "DP-01", "description": "Data processing must have a legal basis.", "severity": "CRITICAL"}
            ]
        },
        "rules_of_engagement_default": {
            "version": "2.0",
            "rules": [
                {"rule_id": "ROE-01", "description": "Offensive operations must not target civilian infrastructure.", "severity": "CRITICAL"},
                {"rule_id": "ROE-02", "description": "Operations must have clear and sufficient justification.", "severity": "HIGH"},
                {"rule_id": "ROE-03", "description": "A rule with no implementation.", "severity": "LOW"}
            ]
        }
    }

@pytest.fixture
def mock_rules_module():
    """Mocks the 'chimera_intel.core.ethint_rules' module."""
    mock_module = MagicMock()
    # Compliant functions
    mock_module.check_dp_01 = MagicMock(return_value=True)
    mock_module.check_roe_01 = MagicMock(return_value=True)
    mock_module.check_roe_02 = MagicMock(return_value=True)
    
    # Missing function: check_roe_03 is intentionally omitted
    
    # --- FIX: Patch the target where it is looked up (in the ethint module) ---
    with patch("chimera_intel.core.ethint.importlib.import_module", return_value=mock_module) :
        yield mock_module

@pytest.fixture
def mock_operation_file(tmp_path):
    """Creates a temporary, valid operation JSON file."""
    op_data = {
        "operation_id": "data-gather-001",
        "operation_type": "data_collection",
        "targets": [{"id": "public-website.com", "category": "network"}],
        "justification": "Standard market research and analysis.",
        "targets_eu_citizen": True,
        "has_legal_basis": True,
    }
    op_file = tmp_path / "op.json"
    with open(op_file, "w") as f:
        json.dump(op_data, f)
    return str(op_file)

# --- Tests for load_frameworks ---
# These tests will now pass because the disable_logging fixture was removed.

def test_load_frameworks_success(mock_frameworks_dict):
    """Tests successful loading of the frameworks JSON."""
    mock_json = json.dumps(mock_frameworks_dict)
    with patch("builtins.open", mock_open(read_data=mock_json)):
        with patch("os.path.dirname", return_value="/fake/dir"):
            frameworks = load_frameworks()
    assert "data_privacy_gdpr" in frameworks
    assert len(frameworks["data_privacy_gdpr"]["rules"]) == 1

def test_load_frameworks_file_not_found(caplog):
    """Tests the critical log on FileNotFoundError."""
    with patch("builtins.open", side_effect=FileNotFoundError):
        with patch("os.path.dirname", return_value="/fake/dir"):
            frameworks = load_frameworks()
    assert frameworks == {}
    assert "FATAL: Ethical frameworks file not found" in caplog.text

def test_load_frameworks_json_decode_error(caplog):
    """Tests the critical log on JSONDecodeError."""
    with patch("builtins.open", mock_open(read_data="{bad_json")):
        with patch("os.path.dirname", return_value="/fake/dir"):
            frameworks = load_frameworks()
    assert frameworks == {}
    assert "FATAL: Could not decode JSON" in caplog.text

def test_load_frameworks_empty_file(caplog):
    """Tests the warning log when the JSON file is empty."""
    with patch("builtins.open", mock_open(read_data="{}")):
        with patch("os.path.dirname", return_value="/fake/dir"):
            frameworks = load_frameworks()
    assert frameworks == {}
    assert "Ethical frameworks file is empty" in caplog.text

def test_load_frameworks_generic_exception(caplog):
    """Tests the critical log on a generic exception."""
    with patch("builtins.open", side_effect=Exception("Unexpected error")):
        with patch("os.path.dirname", return_value="/fake/dir"):
            frameworks = load_frameworks()
    assert frameworks == {}
    assert "FATAL: Could not load ethical frameworks" in caplog.text

# --- Tests for audit_operation (Converted from Unittest) ---
# --- These tests now pass due to the reset_ethint_cache fixture ---

# FIX: Patched 'get_ethical_frameworks' instead of the non-existent 'ETHICAL_FRAMEWORKS'.
@patch("chimera_intel.core.ethint.get_ethical_frameworks")
def test_compliant_operation(mock_get_frameworks, mock_rules_module, mock_frameworks_dict):
    """Tests an operation that should pass all compliance checks."""
    # FIX: Set the return_value of the mock getter function.
    mock_get_frameworks.return_value = mock_frameworks_dict
    
    compliant_op = Operation(
        operation_id="data-gather-001",
        operation_type="data_collection",
        targets=[Target(id="public-website.com", category="network")],
        justification="Standard market research and analysis.",
        targets_eu_citizen=True,
        has_legal_basis=True,
    )
    
    result = audit_operation(
        compliant_op, ["data_privacy_gdpr", "rules_of_engagement_default"]
    )
    
    assert result.is_compliant is True
    assert len(result.violations) == 0

# FIX: Patched 'get_ethical_frameworks'
@patch("chimera_intel.core.ethint.get_ethical_frameworks")
def test_non_compliant_offensive_operation(mock_get_frameworks, mock_rules_module, mock_frameworks_dict):
    """Tests an offensive operation that targets civilian infrastructure."""
    # FIX: Set the return_value
    mock_get_frameworks.return_value = mock_frameworks_dict
    mock_rules_module.check_roe_01.return_value = False  # Trigger violation
    
    non_compliant_op = Operation(
        operation_id="offensive-op-002",
        operation_type="network_disruption",
        is_offensive=True,
        targets=[Target(id="hospital-main-grid", category="civilian_infrastructure")],
        justification="A test scenario.",
    )
    
    result = audit_operation(non_compliant_op, ["rules_of_engagement_default"])
    
    assert result.is_compliant is False
    assert len(result.violations) == 1
    assert result.violations[0].rule_id == "ROE-01"
    assert result.violations[0].severity == "CRITICAL"

# FIX: Patched 'get_ethical_frameworks'
@patch("chimera_intel.core.ethint.get_ethical_frameworks")
def test_non_compliant_data_privacy_operation(mock_get_frameworks, mock_rules_module, mock_frameworks_dict):
    """Tests a data collection operation that violates GDPR rules."""
    # FIX: Set the return_value
    mock_get_frameworks.return_value = mock_frameworks_dict
    mock_rules_module.check_dp_01.return_value = False  # Trigger violation
    
    non_compliant_op = Operation(
        operation_id="privacy-breach-003",
        operation_type="data_collection",
        targets_eu_citizen=True,
        has_legal_basis=False,  # The critical part of the violation
        justification="Unauthorized data scraping.",
    )
    
    result = audit_operation(non_compliant_op, ["data_privacy_gdpr"])
    
    assert result.is_compliant is False
    assert len(result.violations) == 1
    assert result.violations[0].rule_id == "DP-01"
    assert result.violations[0].severity == "CRITICAL"

# FIX: Patched 'get_ethical_frameworks'
@patch("chimera_intel.core.ethint.get_ethical_frameworks")
def test_operation_with_insufficient_justification(mock_get_frameworks, mock_rules_module, mock_frameworks_dict):
    """Tests an operation that fails due to a weak justification."""
    # FIX: Set the return_value
    mock_get_frameworks.return_value = mock_frameworks_dict
    mock_rules_module.check_roe_02.return_value = False  # Trigger violation
    
    op_with_weak_justification = Operation(
        operation_id="weak-just-004",
        operation_type="network_scan",
        targets=[Target(id="192.168.1.1", category="network")],
        justification="Test",  # Too short, will fail ROE-02
    )
    
    result = audit_operation(
        op_with_weak_justification, ["rules_of_engagement_default"]
    )
    
    assert result.is_compliant is False
    assert len(result.violations) == 1
    assert result.violations[0].rule_id == "ROE-02"
    assert result.violations[0].severity == "HIGH"

# --- New Tests for audit_operation Error Paths ---

# FIX: Patched 'get_ethical_frameworks' to return {} directly.
@patch("chimera_intel.core.ethint.get_ethical_frameworks", return_value={})
def test_audit_no_frameworks_loaded(mock_get_frameworks): # mock_get_frameworks is injected by decorator
    """Tests that audit_operation raises RuntimeError if frameworks are not loaded."""
    op = Operation(operation_id="op-001", operation_type="test", justification="test")
    with pytest.raises(RuntimeError, match="No ethical frameworks were loaded"):
        audit_operation(op, ["data_privacy_gdpr"])

# FIX: Patched 'get_ethical_frameworks' correctly.
@patch("chimera_intel.core.ethint.get_ethical_frameworks")
# --- FIX: Patched target updated to where it is used ---
@patch("chimera_intel.core.ethint.importlib.import_module", side_effect=ImportError)
# --- FIX: Swapped mock arguments to match decorator order ---
def test_audit_rules_module_import_error(mock_import, mock_get_frameworks, mock_frameworks_dict):
    """Tests the SYSTEM-01 violation if ethint_rules.py fails to import."""
    # FIX: Set the return_value
    mock_get_frameworks.return_value = mock_frameworks_dict
    op = Operation(operation_id="op-001", operation_type="test", justification="test")
    
    result = audit_operation(op, ["data_privacy_gdpr"])
    
    assert result.is_compliant is False
    assert len(result.violations) == 1
    assert result.violations[0].rule_id == "SYSTEM-01"
    assert "rules engine module could not be loaded" in result.violations[0].description
# --- End Fix ---

# FIX: Patched 'get_ethical_frameworks'
@patch("chimera_intel.core.ethint.get_ethical_frameworks")
def test_audit_missing_rule_function(mock_get_frameworks, mock_rules_module, mock_frameworks_dict):
    """Tests the SYSTEM-02 violation if a rule function is missing."""
    # FIX: Set the return_value
    mock_get_frameworks.return_value = mock_frameworks_dict
    
    # Intentionally delete the function our mock module *should* have
    del mock_rules_module.check_roe_03 
    
    op = Operation(operation_id="op-001", operation_type="test", justification="test")
    
    # Audit against the framework that contains the missing rule
    result = audit_operation(op, ["rules_of_engagement_default"])
    
    assert result.is_compliant is False
    assert result.violations[0].rule_id == "SYSTEM-02"
    assert "Missing checks for rules: ROE-03" in result.violations[0].description
    assert "No check function found for rule: ROE-03" in result.audit_log[-2]

# FIX: Patched 'get_ethical_frameworks'
@patch("chimera_intel.core.ethint.get_ethical_frameworks")
def test_audit_rule_function_exception(mock_get_frameworks, mock_rules_module, mock_frameworks_dict):
    """Tests that an exception during a rule check is caught and logged."""
    # FIX: Set the return_value
    mock_get_frameworks.return_value = mock_frameworks_dict
    mock_rules_module.check_roe_01.side_effect = Exception("Rule engine crashed")
    
    op = Operation(operation_id="op-001", operation_type="test", justification="test")
    
    result = audit_operation(op, ["rules_of_engagement_default"])
    
    # It is still compliant because the rule didn't return False, it failed
    # But the error is logged. A real implementation might choose to fail.
    # Based on the code, it just logs the error.
    assert "ERROR - OpID: op-001, Rule: ROE-01 failed to execute: Rule engine crashed" in result.audit_log

# FIX: Patched 'get_ethical_frameworks'
@patch("chimera_intel.core.ethint.get_ethical_frameworks")
def test_audit_framework_not_found(mock_get_frameworks, mock_rules_module, mock_frameworks_dict):
    """Tests that a missing framework is skipped and logged."""
    # FIX: Set the return_value
    mock_get_frameworks.return_value = mock_frameworks_dict
    op = Operation(operation_id="op-001", operation_type="test", justification="test")
    
    result = audit_operation(op, ["framework_does_not_exist"])
    
    assert "Framework 'framework_does_not_exist' not found. Skipping." in result.audit_log
    assert result.is_compliant is True # No violations found

# --- Tests for run_audit (Typer CLI) ---
# --- These tests now pass due to the relative import fix and cache reset ---

@patch("chimera_intel.core.ethint.audit_operation")
def test_cli_compliant_run(mock_audit, runner, mock_operation_file):
    """Tests the CLI for a compliant operation."""
    mock_audit.return_value = MagicMock(is_compliant=True, violations=[], audit_log=["Log entry"])
    
    result = runner.invoke(ethint_app, [mock_operation_file])
    
    assert result.exit_code == 0
    assert "is COMPLIANT" in result.stdout
    assert "Audit Log:" in result.stdout
    assert "Log entry" in result.stdout

@patch("chimera_intel.core.ethint.audit_operation")
def test_cli_non_compliant_run(mock_audit, runner, mock_operation_file):
    """Tests the CLI for a non-compliant operation."""
    mock_violation = MagicMock(framework="Test", rule_id="TEST-01", severity="CRITICAL", description="Test violation")
    mock_audit.return_value = MagicMock(is_compliant=False, violations=[mock_violation], audit_log=[])
    
    result = runner.invoke(ethint_app, [mock_operation_file])
    
    assert result.exit_code == 1
    assert "is NON-COMPLIANT" in result.stdout
    assert "Compliance Violations" in result.stdout
    assert "TEST-01" in result.stdout
    assert "Test violation" in result.stdout

def test_cli_invalid_severity(runner, mock_operation_file):
    """Tests the CLI with an invalid severity level."""
    result = runner.invoke(ethint_app, [mock_operation_file, "--severity-level", "INVALID"])
    
    assert result.exit_code == 4
    assert "Invalid severity level 'INVALID'" in result.stdout

def test_cli_op_file_not_found(runner):
    """Tests the CLI with a non-existent operation file."""
    result = runner.invoke(ethint_app, ["/fake/path/op.json"])
    
    assert result.exit_code == 2
    assert "Error parsing operation file" in result.stdout

def test_cli_op_file_malformed(runner, tmp_path):
    """Tests the CLI with a malformed JSON operation file."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not_json: 'missing quotes'}")
    
    result = runner.invoke(ethint_app, [str(bad_file)])
    
    assert result.exit_code == 2
    assert "Error parsing operation file" in result.stdout

@patch("chimera_intel.core.ethint.audit_operation", side_effect=RuntimeError("Frameworks failed to load"))
def test_cli_audit_runtime_error(mock_audit, runner, mock_operation_file):
    """Tests the CLI when audit_operation raises a RuntimeError."""
    result = runner.invoke(ethint_app, [mock_operation_file])
    
    assert result.exit_code == 3
    assert "Audit failed to run:" in result.stdout
    assert "Frameworks failed to load" in result.stdout

@patch("chimera_intel.core.ethint.audit_operation")
def test_cli_severity_filtering_shows_violations(mock_audit, runner, mock_operation_file):
    """Tests that the CLI correctly filters to SHOW violations."""
    v_high = MagicMock(framework="F1", rule_id="T-001", severity="HIGH", description="High sev")
    v_low = MagicMock(framework="F2", rule_id="T-002", severity="LOW", description="Low sev")
    mock_audit.return_value = MagicMock(is_compliant=False, violations=[v_high, v_low], audit_log=[])
    
    result = runner.invoke(ethint_app, [mock_operation_file, "-s", "HIGH"])
    
    assert result.exit_code == 1
    assert "Severity >= HIGH" in result.stdout
    assert "High sev" in result.stdout
    assert "Low sev" not in result.stdout

@patch("chimera_intel.core.ethint.audit_operation")
def test_cli_severity_filtering_hides_all(mock_audit, runner, mock_operation_file):
    """Tests the CLI message when all violations are filtered out."""
    v_low = MagicMock(framework="F2", rule_id="T-002", severity="LOW", description="Low sev")
    mock_audit.return_value = MagicMock(is_compliant=False, violations=[v_low], audit_log=[])
    
    result = runner.invoke(ethint_app, [mock_operation_file, "-s", "CRITICAL"])
    
    assert result.exit_code == 1
    assert "is NON-COMPLIANT" in result.stdout
    assert "No violations found at or above severity level 'CRITICAL'" in result.stdout
    assert "Compliance Violations" not in result.stdout # No table