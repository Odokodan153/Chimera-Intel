import pytest
import json
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, ANY

# Import the app to be tested
from src.chimera_intel.core.purple_team import purple_team_app
from src.chimera_intel.core import schemas
from src.chimera_intel.core.ai_core import AIResult

# Create a test runner
runner = CliRunner()

# --- MOCK DATA FOR ALL MODULES ---

# AI Mocks
MOCK_AI_CORRELATION = AIResult(
    analysis_text="Critical Gap: Phishing risk high. Strengths: Good SSL.", 
    error=None
)
MOCK_AI_TTP_HUNT = AIResult(
    analysis_text="Defense Rating: Low. Justification: Typosquat domains found.", 
    error=None
)

# Phase 1: Red Team Mock
MOCK_RED_REPORT = {"red_team_analysis": "Potential attack vector: T1566 Phishing"}

# Phase 2: Defensive Mocks (Pydantic models)
MOCK_HIBP_RESULT = schemas.HIBPResult(breaches=[{"Name": "TestBreach"}])
MOCK_TYPO_RESULT = schemas.TyposquatResult(results=[{"domain": "examp1e.com"}])
MOCK_SHODAN_RESULT = schemas.ShodanResult(total_results=1, hosts=[])
MOCK_CT_RESULT = schemas.CTMentorResult(domain="example.com", total_found=1)
MOCK_SSL_RESULT = schemas.SSLLabsResult(report={"status": "READY", "grade": "A"})
MOCK_GITHUB_RESULT = schemas.GitHubLeaksResult(total_count=0)
MOCK_PASTE_RESULT = schemas.PasteResult(count=0)
MOCK_MOZ_RESULT = schemas.MozillaObservatoryResult(grade="F")
MOCK_IAC_RESULT = schemas.IaCScanResult(target_path="/fake/path", total_issues=0)
MOCK_SECRETS_RESULT = schemas.SecretsScanResult(target_path="/fake/path", total_found=0)

# Phase 3: Threat Intel Mocks
MOCK_ACTORS = [{"name": "APT-Test", "industry": "Financial Services"}]
MOCK_ACTOR_TTPS = [{"id": "T1566", "name": "Phishing"}]

# Phase 5: Risk & Sim Mocks
MOCK_RISK_SCORE = {"gap_id": "G-001", "risk_score": 9.0, "rating": "Critical"}
MOCK_SIM_PATH = {"path_id": "P-001", "steps": ["breach", "pivot", "exfil"]}
MOCK_TTP_DETAILS = {"id": "T1566", "name": "Phishing", "description": "..."}


# --- FIXTURE TO PATCH ALL DEPENDENCIES ---

@pytest.fixture(autouse=True)
def mock_all_dependencies():
    """Mocks all external dependencies for all tests in this file."""
    
    # Create MagicMocks for each imported module
    mock_api_keys = MagicMock()
    mock_api_keys.google_api_key = "fake_google_key"
    mock_api_keys.hibp_api_key = "fake_hibp_key"
    mock_api_keys.shodan_api_key = "fake_shodan_key"
    mock_api_keys.github_pat = "fake_github_key"
    mock_api_keys.mobsf_api_key = "fake_mobsf_key"

    mock_ai_core = MagicMock()
    mock_ai_core.generate_swot_from_data.return_value = MOCK_AI_CORRELATION

    mock_red_team = MagicMock()
    mock_red_team.generate_attack_vectors.return_value = MOCK_RED_REPORT

    # Mock all defensive functions
    mock_defensive = MagicMock()
    mock_defensive.check_hibp_breaches.return_value = MOCK_HIBP_RESULT
    mock_defensive.find_typosquatting_dnstwist.return_value = MOCK_TYPO_RESULT
    mock_defensive.analyze_attack_surface_shodan.return_value = MOCK_SHODAN_RESULT
    mock_defensive.monitor_ct_logs.return_value = MOCK_CT_RESULT
    mock_defensive.analyze_ssl_ssllabs.return_value = MOCK_SSL_RESULT
    mock_defensive.search_github_leaks.return_value = MOCK_GITHUB_RESULT
    mock_defensive.search_pastes_api.return_value = MOCK_PASTE_RESULT
    mock_defensive.analyze_mozilla_observatory.return_value = MOCK_MOZ_RESULT
    mock_defensive.scan_iac_files.return_value = MOCK_IAC_RESULT
    mock_defensive.scan_for_secrets.return_value = MOCK_SECRETS_RESULT

    # Mock new integrations
    mock_threat_actor = MagicMock()
    mock_threat_actor.get_actors_by_industry.return_value = MOCK_ACTORS
    
    mock_ttp_mapper = MagicMock()
    mock_ttp_mapper.get_ttps_for_actor.return_value = MOCK_ACTOR_TTPS
    mock_ttp_mapper.get_ttp_details.return_value = MOCK_TTP_DETAILS

    mock_risk = MagicMock()
    mock_risk.calculate_risk_for_gap.return_value = MOCK_RISK_SCORE

    mock_simulator = MagicMock()
    mock_simulator.generate_simulated_paths.return_value = MOCK_SIM_PATH
    
    mock_db = MagicMock()
    mock_db.save_scan_to_db.return_value = None

    # Use patch.dict to replace modules in sys.modules
    with patch.multiple('src.chimera_intel.core.purple_team',
        API_KEYS=mock_api_keys,
        ai_core=mock_ai_core,
        red_team=mock_red_team,
        defensive=mock_defensive,
        threat_actor_intel=mock_threat_actor,
        ttp_mapper=mock_ttp_mapper,
        risk_assessment=mock_risk,
        attack_path_simulator=mock_simulator,
        save_scan_to_db=mock_db
    ) as mocks:
        yield mocks

# --- TEST CASES ---

def test_run_exercise_cli(mock_all_dependencies):
    """
    Test the full, 5-phase `run-exercise` command.
    """
    mocks = mock_all_dependencies # Get the mocked modules
    target_domain = "example.com"
    target_industry = "Financial Services"
    
    result = runner.invoke(purple_team_app, [
        "run-exercise", target_domain,
        "--industry", target_industry
    ])

    # 1. Check exit code and basic output
    assert result.exit_code == 0
    assert "Purple Team Exercise Complete" in result.stdout
    assert "Saving exercise results to database" in result.stdout

    # 2. Verify all 5 phases were called correctly
    mocks['red_team'].generate_attack_vectors.assert_called_once_with(target_domain)
    mocks['defensive'].check_hibp_breaches.assert_called_once() # Spot check
    mocks['threat_actor_intel'].get_actors_by_industry.assert_called_once_with(target_industry)
    mocks['ai_core'].generate_swot_from_data.assert_called_once()
    mocks['risk_assessment'].calculate_risk_for_gap.assert_called_once()
    mocks['attack_path_simulator'].generate_simulated_paths.assert_called_once()
    mocks['save_scan_to_db'].assert_called_once()

    # 3. Check AI prompt content
    ai_prompt = mocks['ai_core'].generate_swot_from_data.call_args[0][0]
    assert "Red Team Report" in ai_prompt
    assert "Defensive Footprint" in ai_prompt
    assert "Threat Intel Report" in ai_prompt
    assert MOCK_RED_REPORT["red_team_analysis"] in ai_prompt
    assert MOCK_TYPO_RESULT.results[0]["domain"] in ai_prompt
    assert MOCK_ACTORS[0]["name"] in ai_prompt

    # 4. Check final report content (spot check)
    output_data = json.loads(result.stdout.split("---")[2])
    assert output_data["exercise_type"] == "full_5_phase"
    assert output_data["phase_1_red_team"] == MOCK_RED_REPORT
    assert output_data["phase_3_threat_intel"]["relevant_actors"] == MOCK_ACTORS
    assert output_data["phase_4_ai_correlation"]["analysis_text"] == MOCK_AI_CORRELATION.analysis_text
    assert output_data["phase_5_risk_simulation"]["risk_assessment_report"]["scored_gaps"][0]["rating"] == "Critical"
    assert output_data["phase_5_risk_simulation"]["attack_simulation_report"]["paths"] == MOCK_SIM_PATH


def test_hunt_ttp_cli(mock_all_dependencies):
    """
    Test the hypothesis-driven `hunt-ttp` command.
    """
    mocks = mock_all_dependencies
    mocks['ai_core'].generate_swot_from_data.return_value = MOCK_AI_TTP_HUNT
    
    ttp_id = "T1566" # Phishing
    target_domain = "example.com"

    result = runner.invoke(purple_team_app, ["hunt-ttp", ttp_id, target_domain])

    assert result.exit_code == 0
    
    # 1. Verify TTP mapper and relevant defensive scans were called
    mocks['ttp_mapper'].get_ttp_details.assert_called_once_with(ttp_id)
    mocks['defensive'].find_typosquatting_dnstwist.assert_called_once_with(target_domain)
    mocks['defensive'].check_hibp_breaches.assert_called_once_with(target_domain, ANY)
    
    # 2. Verify *irrelevant* scans were NOT called
    mocks['defensive'].analyze_attack_surface_shodan.assert_not_called()

    # 3. Verify AI prompt
    ai_prompt = mocks['ai_core'].generate_swot_from_data.call_args[0][0]
    assert "assess the defensive posture" in ai_prompt
    assert MOCK_TTP_DETAILS["name"] in ai_prompt
    assert MOCK_TYPO_RESULT.results[0]["domain"] in ai_prompt

    # 4. Check report output
    output_data = json.loads(result.stdout)
    assert output_data["exercise_type"] == "ttp_hunt"
    assert output_data["ttp_id"] == ttp_id
    assert output_data["ai_assessment"] == MOCK_AI_TTP_HUNT.analysis_text


def test_emulate_actor_cli(mock_all_dependencies):
    """
    Test the CTI-driven `emulate-actor` command.
    """
    mocks = mock_all_dependencies
    
    actor_name = "APT-Test"
    target_domain = "example.com"

    result = runner.invoke(purple_team_app, ["emulate-actor", actor_name, target_domain])
    
    assert result.exit_code == 0

    # 1. Verify TTP mapper was called
    mocks['ttp_mapper'].get_ttps_for_actor.assert_called_once_with(actor_name)
    
    # 2. Verify defensive scans for that actor's TTPs were called
    # (Our mock actor only has T1566)
    mocks['defensive'].find_typosquatting_dnstwist.assert_called_once_with(target_domain)
    
    # 3. Verify other scans were not
    mocks['defensive'].analyze_attack_surface_shodan.assert_not_called()

    # 4. Check report output
    output_data = json.loads(result.stdout.split("---")[2]) # Get JSON part
    assert output_data["exercise_type"] == "actor_emulation"
    assert output_data["actor_name"] == actor_name
    assert len(output_data["ttp_coverage_report"]) == 1
    assert output_data["ttp_coverage_report"][0]["ttp_id"] == MOCK_ACTOR_TTPS[0]["id"]
    assert "typosquatting" in output_data["ttp_coverage_report"][0]["defensive_findings"]