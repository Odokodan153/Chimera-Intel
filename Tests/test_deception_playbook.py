"""
Tests for the deception_playbook orchestrator.
"""

import pytest
import unittest.mock as mock
from typer.testing import CliRunner
from pathlib import Path
import json
# Module to test
from chimera_intel.core.deception_playbook import playbook_app

# A runner for invoking our app
runner = CliRunner()

@pytest.fixture(scope="module")
def temp_media_file():
    """Create a dummy media file and key for testing."""
    media = Path("dummy_video.mp4")
    media.write_bytes(b"dummy video data")
    
    key = Path("dummy_key.pem")
    key.write_bytes(b"dummy key data")
    
    yield media, key
    
    # Cleanup
    media.unlink()
    key.unlink()
    
    # Clean up files created by the playbook
    for f in Path(".").glob("dummy_video*"):
        f.unlink()
    for f in Path(".").glob("debunking_draft_*"):
        f.unlink()
    for f in Path(".").glob("mitigation_plan_*"):
        f.unlink()


def test_deception_playbook_full_run(temp_media_file):
    """
    Test the full run of the `run-deception` command.
    
    We mock the external dependencies:
    1. `forensics_app` (from image_forensics_pipeline)
    2. `response_action_map` (from response)
    3. `vault_app` (from forensic_vault)
    """
    media_file, key_file = temp_media_file

    # 1. Mock the `image_forensics_pipeline.pipeline_app`
    # We patch it at its source location.
    with mock.patch("chimera_intel.core.deception_playbook.forensics_app") as mock_forensics_app:
        
        # 2. Mock the `forensic_vault.vault_app`
        with mock.patch("chimera_intel.core.deception_playbook.vault_app") as mock_vault_app:
            
            # 3. Mock the `response.ACTION_MAP`
            # Create mock functions for each action
            mock_takedown = mock.Mock(name="takedown")
            mock_notify = mock.Mock(name="notify")
            mock_debunk = mock.Mock(name="debunk")
            
            mock_map = {
                "platform_takedown_request": mock_takedown,
                "internal_threat_warning": mock_notify,
                "generate_debunking_script": mock_debunk,
            }
            
            with mock.patch("chimera_intel.core.deception_playbook.response_action_map", mock_map):
                
                # --- Now, execute the command ---
                result = runner.invoke(
                    playbook_app,
                    [
                        "run-deception",
                        str(media_file),
                        "--target", "Test Exec",
                        "--key", str(key_file),
                        "--output", "playbook_report.json"
                    ],
                    catch_exceptions=False
                )
                
                # --- Assertions ---
                
                # Check that the command succeeded
                assert result.exit_code == 0
                assert "PLAYBOOK COMPLETE" in result.stdout
                
                # Step 1: Check Triage was called correctly
                mock_forensics_app.assert_called_once_with(
                    ["run", str(media_file), "--output", "dummy_video_forensics_report.json"],
                    catch_exceptions=False
                )
                
                # Define expected details for response actions
                expected_details = {
                    "media_file": str(media_file),
                    "target": "Test Exec",
                    "confidence": "High (Playbook Triggered)",
                    "incident_type": "deception_playbook"
                }
                
                # Step 2: Check Contain was called
                mock_takedown.assert_called_once_with(expected_details)
                
                # Step 3: Check Notify was called
                mock_notify.assert_called_once_with(expected_details)
                
                # Step 4: Check Public Response was called
                mock_debunk.assert_called_once_with(expected_details)

                # Step 5: Check Preserve was called correctly
                mock_vault_app.assert_called_once_with(
                    [
                        "create-receipt",
                        str(media_file),
                        "--key", str(key_file),
                        "--output", "dummy_video_receipt.json",
                    ],
                    catch_exceptions=False
                )
                
                # Step 6: Check that mitigation file was created
                assert Path("mitigation_plan_Test_Exec.txt").exists()
                
                # Check final report
                report_path = Path("playbook_report.json")
                assert report_path.exists()
                report_data = json.loads(report_path.read_text())
                assert report_data["success"] is True
                assert len(report_data["steps"]) == 6
                assert report_data["steps"][0]["step_name"] == "Triage"
                assert report_data["steps"][5]["step_name"] == "Mitigate"

                report_path.unlink() # clean up