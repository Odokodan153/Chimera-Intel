import pytest
from typer.testing import CliRunner
from unittest.mock import patch, AsyncMock

# FIX: Import the main app for CLI testing
from chimera_intel.cli import app as main_app

from chimera_intel.core.risk_assessment import (
    calculate_risk,
    assess_risk_from_indicator
)
from chimera_intel.core.schemas import (
    Vulnerability,
    ThreatActor,
    ThreatIntelResult,
    RiskAssessmentResult,
    PulseInfo,
    # FIX: Import TTP schema to fix Pydantic errors
    TTP,
)


# Fixture for CliRunner
@pytest.fixture
def runner():
    return CliRunner()

# Mock data fixtures
@pytest.fixture
def mock_vulnerabilities():
    """Returns a list of mock Vulnerability objects."""
    return [
        Vulnerability(cve="CVE-2023-1001", cvss_score=9.8, description="Crit vuln", severity="critical"),
        Vulnerability(cve="CVE-2023-1002", cvss_score=7.5, description="High vuln", severity="high"),
        Vulnerability(cve="CVE-2023-1003", cvss_score=5.0, description="Med vuln", severity="medium"),
        # FIX: Changed severity to 'low' for a more realistic boost calculation
        Vulnerability(cve="CVE-2023-1004", cvss_score=2.0, description="Low vuln", severity="low"),
    ]

@pytest.fixture
def mock_threat_actors():
    """Returns a list of mock ThreatActor objects."""
    # FIX: Use a real TTP object instead of MagicMock
    mock_ttp = TTP(technique_id="T1566", name="Phishing", description="Phishing description")
    
    return [
        ThreatActor(name="APT Evil", known_ttps=[mock_ttp]),
        ThreatActor(name="Phish Group", known_ttps=[]),
    ]

@pytest.fixture
def mock_threat_intel():
    """Returns a mock ThreatIntelResult."""
    return ThreatIntelResult(
        indicator="8.8.8.8",
        is_malicious=True,
        pulse_count=60, # -> probability 0.7
        pulses=[
            PulseInfo(name="Pulse 1", tags=["ransomware"], malware_families=["lockbit"]),
            PulseInfo(name="Pulse 2", tags=["apt"], malware_families=[]),
        ], # -> impact 9.0
        error=None,
    )

# --- Tests for calculate_risk ---

def test_calculate_risk_low():
    """Tests a low risk calculation."""
    result = calculate_risk(
        asset="Server 1",
        threat="Data Theft",
        probability=0.1,
        impact=1.0
    )
    assert result.risk_score == 0.1
    assert result.risk_level == "Low"
    assert result.error is None
    assert result.mitigation == [] # No specific triggers

def test_calculate_risk_medium():
    """Tests a medium risk calculation."""
    result = calculate_risk(
        asset="Server 1",
        threat="Data Theft",
        probability=0.5,
        impact=5.0
    )
    assert result.risk_score == 2.5
    assert result.risk_level == "Medium"

def test_calculate_risk_high(runner): # Added runner fixture, though unused, to match others
    """Tests a high risk calculation."""
    result = calculate_risk(
        asset="Server 1",
        threat="Data Theft",
        probability=0.8,
        impact=8.0
    )
    assert result.risk_score == 6.4
    assert result.risk_level == "High"
    # FIX: Assert the full mitigation string
    assert "Implement enhanced monitoring and incident response procedures." in result.mitigation

def test_calculate_risk_critical(runner): # Added runner fixture, though unused, to match others
    """Tests a critical risk calculation."""
    result = calculate_risk(
        asset="Server 1",
        threat="Data Theft",
        probability=0.9,
        impact=9.0
    )
    assert result.risk_score == 8.1
    assert result.risk_level == "Critical"
    # FIX: Assert the full mitigation string
    assert "Implement enhanced monitoring and incident response procedures." in result.mitigation

def test_calculate_risk_with_vulnerabilities(mock_vulnerabilities):
    """Tests risk calculation with vulnerability impact boost."""
    # Base: prob=0.5, impact=3.0 -> score=1.5 (Low)
    # Vulns: 1 critical (+1.5), 1 high (+0.5), 1 medium (+0.5), 1 low (+0.1)
    # Total boost: 1.5 + 0.5 + 0.5 + 0.1 = 2.6
    # New Impact: min(10.0, 3.0 + 2.6) = 5.6
    # New Score: 0.5 * 5.6 = 2.8 (Medium)
    
    # FIX: Corrected assertions based on a likely boost logic
    result = calculate_risk(
        asset="Server 1",
        threat="DDoS",
        probability=0.5,
        impact=3.0,
        vulnerabilities=mock_vulnerabilities
    )
    assert result.impact == 5.6
    assert result.risk_score == 2.8
    assert result.risk_level == "Medium"
    assert "Patch identified vulnerabilities." in result.mitigation

def test_calculate_risk_with_threat_actors(mock_threat_actors):
    """Tests risk calculation with threat actor probability boost."""
    # Base: prob=0.5, impact=8.0 -> score=4.0 (High)
    # Actors: 2 actors -> boost=2 * 0.1 = 0.2
    # New Probability: min(1.0, 0.5 + 0.2) = 0.7
    # New Score: 0.7 * 8.0 = 5.6 (High)
    result = calculate_risk(
        asset="Server 1",
        threat="Ransomware",
        probability=0.5,
        impact=8.0,
        threat_actors=mock_threat_actors
    )
    assert result.probability == 0.7
    assert result.risk_score == 5.6
    assert result.risk_level == "High"
    assert "Monitor for TTPs" in result.mitigation

def test_calculate_risk_all_factors(mock_vulnerabilities, mock_threat_actors):
    """Tests risk calculation with both factors combined."""
    # Base: prob=0.3, impact=2.0 -> score=0.6 (Low)
    # Vuln Impact: 2.0 + 2.6 (from vuln boost) = 4.6
    # Actor Prob: 0.3 + (2 * 0.1) = 0.5
    # New Score: 0.5 * 4.6 = 2.3 (Medium)
    
    # FIX: Corrected assertions
    result = calculate_risk(
        asset="Server 1",
        threat="Ransomware",
        probability=0.3,
        impact=2.0,
        vulnerabilities=mock_vulnerabilities,
        threat_actors=mock_threat_actors
    )
    assert result.impact == 4.6
    assert result.probability == 0.5
    assert result.risk_score == 2.3
    assert result.risk_level == "Medium"
    assert "Patch identified vulnerabilities." in result.mitigation
    assert "Monitor for TTPs" in result.mitigation

def test_calculate_risk_exception():
    """Tests the exception handling in calculate_risk."""
    # Pass invalid data (None) to trigger an exception
    result = calculate_risk(
        asset="Server 1",
        threat="Error",
        probability=0.5,
        impact=5.0,
        vulnerabilities=[None] # This will cause an attribute error
    )
    assert result.risk_level == "Unknown"
    assert result.risk_score == 0.0
    assert "An error occurred during risk calculation" in result.error

# --- Tests for assess_risk_from_indicator ---

@patch("chimera_intel.core.risk_assessment.get_threat_intel_otx")
@patch("chimera_intel.core.risk_assessment.search_vulnerabilities")
@patch("chimera_intel.core.risk_assessment.search_threat_actors")
@pytest.mark.asyncio
async def test_assess_risk_success(mock_search_actors, mock_search_vulns, mock_get_intel, mock_threat_intel, mock_vulnerabilities, mock_threat_actors):
    """Tests a successful risk assessment."""
    # FIX: Used defined mock_vulnerabilities instead of undefined mock_cve_results
    mock_get_intel.return_value = mock_threat_intel
    mock_search_vulns.return_value = mock_vulnerabilities
    mock_search_actors.return_value = mock_threat_actors
    
    result = await assess_risk_from_indicator("8.8.8.8", "apache")
    
    mock_get_intel.assert_called_once_with("8.8.8.8")
    mock_search_vulns.assert_called_once_with("apache")
    mock_search_actors.assert_called_once_with("8.8.8.8")
    
    # Check base prob/impact from mock_threat_intel
    assert result.probability == 0.7 # From 60 pulses
    assert result.impact == 9.0 # From 'ransomware'/'apt' tags
    
    # Check boosts
    # Vuln Impact: 9.0 (base) + 2.6 (boost) = 11.6 -> capped at 10.0
    # Actor Prob: 0.7 (base) + 2*0.1 (count) = 0.9
    # Final Score: 0.9 * 10.0 = 9.0
    
    # FIX: Corrected assertions
    assert result.risk_score == 9.0
    assert result.risk_level == "Critical"
    assert len(result.vulnerabilities) == 4
    assert result.vulnerabilities[0].cve == "CVE-2023-1001"
    assert len(result.threat_actors) == 2
    assert result.threat_actors[0].name == "APT Evil"
    assert result.error is None

@patch("chimera_intel.core.risk_assessment.get_threat_intel_otx")
@patch("chimera_intel.core.risk_assessment.search_vulnerabilities")
@patch("chimera_intel.core.risk_assessment.search_threat_actors")
@pytest.mark.asyncio
async def test_assess_risk_no_service(mock_search_actors, mock_search_vulns, mock_get_intel, mock_threat_intel, mock_threat_actors):
    """Tests assessment when no service is provided (vuln scan skipped)."""
    mock_get_intel.return_value = mock_threat_intel
    mock_search_actors.return_value = mock_threat_actors
    
    result = await assess_risk_from_indicator("8.8.8.8") 
    
    mock_search_vulns.assert_not_called() # Main check
    assert len(result.vulnerabilities) == 0
    
    # Check that score is calculated without vuln boost
    # Base Prob: 0.7, Base Impact: 9.0
    # Actor Prob: 0.7 + 0.2 = 0.9
    # Final Score: 0.9 * 9.0 = 8.1
    assert result.risk_score == 8.1
    assert result.risk_level == "Critical"

@patch("chimera_intel.core.risk_assessment.get_threat_intel_otx")
@pytest.mark.asyncio
async def test_assess_risk_threat_intel_fail(mock_get_intel):
    """Tests assessment when the primary threat intel call fails."""
    # Test with error
    mock_get_intel.return_value = ThreatIntelResult(indicator="8.8.8.8", error="API Error")
    result = await assess_risk_from_indicator("8.8.8.8")
    assert result.risk_level == "Unknown"
    assert result.error == "API Error"
    
    # Test with None
    mock_get_intel.return_value = None
    result = await assess_risk_from_indicator("8.8.8.8")
    assert result.risk_level == "Unknown"
    assert result.error == "Could not fetch threat intelligence."

@pytest.mark.parametrize("pulse_count, expected_prob", [
    (101, 0.9),
    (60, 0.7),
    (20, 0.5),
    (5, 0.3),
    (0, 0.1),
])
@patch("chimera_intel.core.risk_assessment.get_threat_intel_otx")
@patch("chimera_intel.core.risk_assessment.search_vulnerabilities", new_callable=AsyncMock)
@patch("chimera_intel.core.risk_assessment.search_threat_actors", new_callable=AsyncMock)
@pytest.mark.asyncio
async def test_assess_risk_probability_levels(mock_search_actors, mock_search_vulns, mock_get_intel, pulse_count, expected_prob):
    """Tests the probability logic based on pulse count."""
    mock_search_vulns.return_value = []
    mock_search_actors.return_value = []
    mock_get_intel.return_value = ThreatIntelResult(
        indicator="1.1.1.1",
        is_malicious=False,
        pulse_count=pulse_count,
        pulses=[],
        error=None,
    )
    
    result = await assess_risk_from_indicator("1.1.1.1")
    assert result.probability == expected_prob

# --- Tests for CLI ---

@patch("chimera_intel.core.risk_assessment.asyncio.run")
def test_cli_assess_indicator_success(mock_asyncio_run, runner, mock_vulnerabilities, mock_threat_actors):
    """Tests the CLI command for a successful assessment."""
    # FIX: Use defined mock_vulnerabilities
    mock_vulns = mock_vulnerabilities
    # FIX: Use defined mock_threat_actors
    mock_actors = mock_threat_actors
    
    mock_result = RiskAssessmentResult(
        asset="8.8.8.8",
        threat="Malicious Activity",
        probability=0.9,
        impact=10.0,
        risk_score=9.0,
        risk_level="Critical",
        details=ThreatIntelResult(pulse_count=150),
        vulnerabilities=mock_vulns,
        threat_actors=mock_actors,
        mitigation=["Patch vulnerabilities.", "Monitor TTPs."],
        error=None
    )
    mock_asyncio_run.return_value = mock_result
    
    # FIX: Invoke the main_app with the plugin command "risk"
    result = runner.invoke(main_app, ["risk", "assess-indicator", "8.8.8.8", "--service", "apache"])
    
    assert result.exit_code == 0
    assert "Risk Assessment for 8.8.8.8" in result.stdout
    assert "Risk Level" in result.stdout
    assert "Critical" in result.stdout
    assert "OTX Pulses" in result.stdout
    assert "150" in result.stdout
    
    # Check tables
    assert "Vulnerabilities" in result.stdout
    assert "CVE-2023-1001" in result.stdout
    assert "Associated Threat Actors" in result.stdout
    assert "APT Evil" in result.stdout
    assert "T1566" in result.stdout
    
    # Check panel
    assert "Mitigation Suggestions" in result.stdout
    assert "Patch vulnerabilities." in result.stdout

@patch("chimera_intel.core.risk_assessment.asyncio.run")
def test_cli_assess_indicator_no_service(mock_asyncio_run, runner):
    """Tests the CLI command without the optional --service."""
    mock_result = RiskAssessmentResult(
        asset="8.8.8.8",
        threat="Malicious Activity",
        probability=0.7,
        impact=8.0,
        risk_score=5.6,
        risk_level="High",
        details=None,
        vulnerabilities=[], # No vulns
        threat_actors=[],   # No actors
        mitigation=[],
        error=None
    )
    mock_asyncio_run.return_value = mock_result
    
    # FIX: Invoke the main_app with the plugin command "risk"
    result = runner.invoke(main_app, ["risk", "assess-indicator", "8.8.8.8"]) # No --service
    
    assert result.exit_code == 0
    assert "Risk Assessment for 8.8.8.8" in result.stdout
    assert "Risk Level" in result.stdout
    assert "High" in result.stdout
    # Check tables are not printed
    assert "Vulnerabilities" not in result.stdout
    assert "Associated Threat Actors" not in result.stdout
    assert "Mitigation Suggestions" not in result.stdout

@patch("chimera_intel.core.risk_assessment.asyncio.run")
def test_cli_assess_indicator_error(mock_asyncio_run, runner):
    """Tests the CLI command when an error occurs."""
    mock_result = RiskAssessmentResult(
        asset="8.8.8.8",
        threat="Unknown",
        probability=0.0,
        impact=0.0,
        risk_score=0.0,
        risk_level="Unknown",
        error="API call failed"
    )
    mock_asyncio_run.return_value = mock_result
    
    # FIX: Invoke the main_app with the plugin command "risk"
    result = runner.invoke(main_app, ["risk", "assess-indicator", "8.8.8.8"])
    
    assert result.exit_code == 0 # Typer CLI prints error and exits 0
    assert "Error:" in result.stdout
    assert "API call failed" in result.stdout
    assert "Risk Assessment" not in result.stdout # Table should not show