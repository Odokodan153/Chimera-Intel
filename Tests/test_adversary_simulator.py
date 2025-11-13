# Tests/test_adversary_simulator.py

import unittest
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

from src.chimera_intel.core.schemas import RedTeamPlan, EmulationLabTarget
from src.chimera_intel.core import adversary_simulator

# Mock data
mock_config = {
    "caldera.url": "https://caldera.local:8888",
}
mock_api_keys = MagicMock()
mock_api_keys.caldera_api_key = "test-api-key"

mock_abilities = [
    {
        "ability_id": "abc-123",
        "name": "Find Files",
        "description": "Finds files",
        "tactic": "T1083",
    },
    {
        "ability_id": "xyz-789",
        "name": "Exfil Data",
        "description": "Exfiltrates data",
        "tactic": "T1041",
    },
]

mock_operation = {
    "id": "op-id-123",
    "name": "Test Operation",
    "state": "running",
}

mock_op_report = {
    "id": "op-id-123",
    "name": "Test Operation",
    "state": "finished",
}

mock_op_links = [
    {
        "ability": {"ability_id": "abc-123", "name": "Find Files", "tactic": "T1083"},
        "command": "find /",
        "status": 0, # Success
        "output": "/etc/passwd",
        "decide": "2025-11-13T17:00:00Z",
    }
]

@pytest.mark.asyncio
class TestAdversarySimulator(unittest.TestCase):

    def setUp(self):
        # Patch dependencies
        self.config_patch = patch('src.chimera_intel.core.adversary_simulator.get_config', 
                                  side_effect=lambda key: mock_config[key])
        self.api_keys_patch = patch('src.chimera_intel.core.adversary_simulator.API_KEYS', 
                                    mock_api_keys)
        self.gemini_patch = patch('src.chimera_intel.core.adversary_simulator.GeminiClient')
        
        self.mock_get_config = self.config_patch.start()
        self.mock_api_keys = self.api_keys_patch.start()
        self.mock_gemini_client_cls = self.gemini_patch.start()
        
        self.mock_gemini_client = MagicMock()
        self.mock_gemini_client.generate_response = MagicMock(
            return_value='["abc-123", "xyz-789"]'
        )
        self.mock_gemini_client_cls.return_value = self.mock_gemini_client

    def tearDown(self):
        self.config_patch.stop()
        self.api_keys_patch.stop()
        self.gemini_patch.stop()

    @patch('src.chimera_intel.core.adversary_simulator.httpx.AsyncClient')
    async def test_caldera_client_get_abilities(self, mock_async_client_cls):
        mock_client = MagicMock()
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.json.return_value = mock_abilities
        mock_client.request = AsyncMock(return_value=mock_response)
        
        # This context manager setup is how httpx.AsyncClient is typically mocked
        mock_async_client_cls.return_value.__aenter__.return_value = mock_client
        
        client = adversary_simulator.CalderaClient()
        abilities = await client.get_all_abilities()
        
        mock_client.request.assert_called_once_with("GET", "/api/v2/abilities")
        self.assertEqual(abilities, mock_abilities)

    @patch('src.chimera_intel.core.adversary_simulator.httpx.AsyncClient')
    async def test_run_simulation_success(self, mock_async_client_cls):
        mock_client = MagicMock()
        
        # Setup multiple return values for the mocked client
        mock_responses = {
            "/api/v2/abilities": mock_abilities,
            "/api/v2/adversaries": {"adversary_id": "adv-id-456"},
            "/api/v2/operations": mock_operation,
            f"/api/v2/operations/{mock_operation['id']}": mock_op_report,
            f"/api/v2/operations/{mock_operation['id']}/links": mock_op_links,
        }

        async def mock_request(method, endpoint, json=None):
            mock_resp = MagicMock(spec=httpx.Response)
            
            # Find matching response
            if endpoint in mock_responses:
                mock_resp.json.return_value = mock_responses[endpoint]
            elif endpoint == f"/api/v2/operations/{mock_operation['id']}" and method == "GET":
                 # This handles the polling
                mock_resp.json.return_value = mock_op_report
            else:
                 mock_resp.json.return_value = {"error": "not found"}
                 
            return mock_resp
            
        mock_client.request = AsyncMock(side_effect=mock_request)
        mock_async_client_cls.return_value.__aenter__.return_value = mock_client
        
        plan = RedTeamPlan(target_id="test", ttps=["T1083"], narrative="Find files")
        target = EmulationLabTarget(
            target_id="test-target", ip_address="1.2.3.4", hostname="host",
            metadata={"caldera_paw": "test-paw-123"}
        )
        
        result = await adversary_simulator.run_simulation(plan, target)
        
        # 1. Check AI translation was called
        self.mock_gemini_client.generate_response.assert_called_once()
        
        # 2. Check that an operation was created
        create_op_call = [c for c in mock_client.request.call_args_list if c.args[1] == "/api/v2/operations"]
        self.assertTrue(len(create_op_call) > 0)
        self.assertEqual(create_op_call[0].kwargs['json']['agents'][0]['paw'], "test-paw-123")

        # 3. Check the final parsed result
        self.assertEqual(result.status, "finished")
        self.assertEqual(result.operation_id, "op-id-123")
        self.assertEqual(result.target_paw, "test-paw-123")
        self.assertEqual(len(result.executed_steps), 1)
        self.assertEqual(result.executed_steps[0].ability_id, "abc-123")
        self.assertEqual(result.executed_steps[0].status, "success")
        self.assertEqual(result.executed_steps[0].output, "/etc/passwd")

    async def test_run_simulation_no_paw(self):
        plan = RedTeamPlan(target_id="test", ttps=[], narrative="test")
        target = EmulationLabTarget(
            target_id="no-paw-target", ip_address="1.2.3.4", hostname="host",
            metadata={} # Missing 'caldera_paw'
        )
        
        result = await adversary_simulator.run_simulation(plan, target)
        
        self.assertEqual(result.status, "failed")
        self.assertIn("'caldera_paw' not found", result.error_message)

if __name__ == "__main__":
    unittest.main()