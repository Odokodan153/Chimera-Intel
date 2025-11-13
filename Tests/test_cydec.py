# Tests/test_cydec.py
"""
Tests for the CYDEC (Cyber Deception) module.
"""

import unittest
import os
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, mock_open

# Module to test
from chimera_intel.core.cydec import cydec_app, HONEY_ASSET_DIR, HONEY_ASSET_PORT

runner = CliRunner()

class TestCydec(unittest.TestCase):

    @patch('chimera_intel.core.cydec.get_llm_client')
    @patch('typer.prompt')
    def test_emulate_ai_shell(self, mock_prompt, mock_get_llm):
        """Test the AI shell emulator loop."""
        
        # Configure mocks
        mock_llm = MagicMock()
        mock_llm.generate.side_effect = [
            "drwxr-xr-x 2 root root 4096 Jan 1 09:00 bin",
            "cat: /etc/shadow: Permission denied"
        ]
        mock_get_llm.return_value = mock_llm
        
        # Simulate user inputs
        mock_prompt.side_effect = ["ls -l", "cat /etc/shadow", "exit"]

        result = runner.invoke(cydec_app, ["emulate-ai-shell"])

        self.assertEqual(result.exit_code, 0)
        
        # Check that the AI was called with the correct prompts
        self.assertIn("User command: ls -l", mock_llm.generate.call_args_list[0][0][0])
        self.assertIn("User command: cat /etc/shadow", mock_llm.generate.call_args_list[1][0][0])
        
        # Check that the AI's responses were printed
        self.assertIn("drwxr-xr-x 2 root root 4096 Jan 1 09:00 bin", result.stdout)
        self.assertIn("cat: /etc/shadow: Permission denied", result.stdout)
        self.assertIn("...Session closed.", result.stdout)


    @patch('chimera_intel.core.cydec.get_arg_service')
    @patch('chimera_intel.core.cydec.generate_synthetic_profile')
    def test_generate_honey_graph(self, mock_gen_profile, mock_get_arg):
        """Test the honey-graph generation."""
        
        # Configure mocks
        mock_arg = MagicMock()
        mock_get_arg.return_value = mock_arg
        
        mock_profile = MagicMock()
        mock_profile.name = "Alex Chen"
        mock_profile.dict.return_value = {"name": "Alex Chen", "title": "Tester", "is_honeypot": True}
        mock_gen_profile.return_value = mock_profile

        result = runner.invoke(
            cydec_app, 
            ["generate-honey-graph", "--names", "Alex Chen", "--company", "AcmeCorp"]
        )

        self.assertEqual(result.exit_code, 0)
        
        # Check that a profile was generated
        mock_gen_profile.assert_called_with(name="Alex Chen")
        
        # Check that the persona was added to the graph
        mock_arg.add_node.assert_called_with(
            ntype="Persona",
            name="Alex Chen",
            name="Alex Chen",
            title="Tester",
            is_honeypot=True
        )
        
        # Check that the edge to the company was added
        mock_arg.add_edge.assert_called_with(
            src="Alex Chen",
            dest="AcmeCorp",
            etype="WORKS_AT",
            source="CYDEC Honey-Graph"
        )
        self.assertIn("Injected persona: Alex Chen", result.stdout)


    @patch('chimera_intel.core.cydec.get_llm_client')
    @patch('chimera_intel.core.cydec._start_tracking_server')
    @patch('chimera_intel.core.cydec.os.makedirs')
    @patch('builtins.open', new_callable=mock_open)
    def test_deploy_decoy_document(self, mock_file, mock_makedirs, mock_start_server, mock_get_llm):
        """Test the AI decoy document deployment."""
        
        # Configure mocks
        mock_llm = MagicMock()
        mock_llm.generate.return_value = "This is a secret merger document."
        mock_get_llm.return_value = mock_llm
        
        test_filename = "Test_Strategy.txt"
        test_id = "test-doc-001"
        
        result = runner.invoke(
            cydec_app, 
            ["deploy-decoy-document", test_filename, "--id", test_id]
        )

        self.assertEqual(result.exit_code, 0)
        
        # Check that AI was called
        mock_llm.generate.assert_called_once()
        
        # Check that directory was created
        mock_makedirs.assert_called_with(HONEY_ASSET_DIR, exist_ok=True)
        
        # Check that file was written
        expected_path = os.path.join(HONEY_ASSET_DIR, f"{test_id}-{test_filename}")
        mock_file.assert_called_with(expected_path, "w", encoding="utf-8")
        
        # Check that tracking server was started
        mock_start_server.assert_called_with(port=HONEY_ASSET_PORT)
        
        # Check that the correct URL was printed
        expected_url = f"http://127.0.0.1:{HONEY_ASSET_PORT}/{test_id}-{test_filename}"
        self.assertIn(expected_url, result.stdout)
        self.assertIn("Decoy document deployed successfully!", result.stdout)

if __name__ == '__main__':
    unittest.main()