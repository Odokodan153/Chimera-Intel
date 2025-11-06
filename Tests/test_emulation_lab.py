import pytest
import json
import yaml
from typer.testing import CliRunner
from unittest.mock import patch
from chimera_intel.core.emulation_lab import lab_app, provision_emulation_lab

runner = CliRunner()

@pytest.fixture
def sample_json_plan():
    """A mock plan in JSON format."""
    return {"display_name": "Test Phishing Plan", "steps": ["..."]}

@pytest.fixture
def sample_yaml_plan():
    """A mock plan in Atomic (YAML) format."""
    return {"attack_technique": "T1566", "display_name": "Test TTP Plan"}
    
def test_provision_emulation_lab_json(sample_json_plan):
    """Tests provisioning from a JSON plan."""
    with runner.isolated_filesystem():
        plan_path = "plan.json"
        with open(plan_path, "w") as f:
            json.dump(sample_json_plan, f)
            
        profile = {"os": "windows_10", "services": ["mssql"]}
        
        lab = provision_emulation_lab(plan_path, profile, dry_run=True)
        
        assert lab.status == "running"
        assert lab.target_profile["os"] == "windows_10"
        assert "Test Phishing Plan" in lab.emulation_plan["display_name"]
        assert "10.0.0." in lab.ip_address

def test_provision_emulation_lab_yaml(sample_yaml_plan):
    """Tests provisioning from a YAML plan."""
    with runner.isolated_filesystem():
        plan_path = "plan.yaml"
        with open(plan_path, "w") as f:
            yaml.dump(sample_yaml_plan, f)
            
        profile = {"os": "linux", "services": ["apache"]}
        
        lab = provision_emulation_lab(plan_path, profile, dry_run=True)
        
        assert lab.status == "running"
        assert lab.target_profile["services"] == ["apache"]
        assert "Test TTP Plan" in lab.emulation_plan["display_name"]

def test_cli_provision(sample_json_plan):
    """Tests the CLI 'provision' command."""
    with runner.isolated_filesystem():
        plan_path = "plan.json"
        with open(plan_path, "w") as f:
            json.dump(sample_json_plan, f)
            
        result = runner.invoke(
            lab_app,
            [
                "provision",
                plan_path,
                "--target-os", "win_server_2019",
                "--service", "iis",
                "--service", "mssql"
            ]
        )
        
        assert result.exit_code == 0
        assert "Provisioning emulation lab for plan: 'Test Phishing Plan'" in result.stdout
        assert "Provisioning replica VM (OS: win_server_2019)..." in result.stdout
        assert "Installing service: iis..." in result.stdout
        assert "Installing service: mssql..." in result.stdout
        assert "Dry-run mode" in result.stdout
        assert '"status": "running"' in result.stdout

def test_cli_destroy():
    """Tests the CLI 'destroy' command."""
    result = runner.invoke(lab_app, ["destroy", "lab-12345"])
    
    assert result.exit_code == 0
    assert "Destroying lab environment 'lab-12345'" in result.stdout
    assert "Lab environment destroyed" in result.stdout
    assert '"status": "destroyed"' in result.stdout