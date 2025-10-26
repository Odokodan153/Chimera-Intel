import unittest
from unittest.mock import MagicMock, patch, AsyncMock
import sys
import os
import pytest
from typer.testing import CliRunner

# Import the class and CLI app from the source file
from chimera_intel.core.aia_framework import AIAFramework, app as aia_cli_app
from chimera_intel.core.schemas import AnalysisResult, ReasoningOutput
# Add the project's root directory to the Python path to ensure imports work correctly

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from chimera_intel.core.aia_framework import (
    create_initial_plans,
    synthesize_and_refine,
    Plan,
    Task,
)

class MockModule:
    def __init__(self, name="mock_module"):
        self.name = name
        self.run = AsyncMock(side_effect=mock_module_run)

@pytest.fixture
def framework():
    """Provides a fresh instance of AIAFramework for each test."""
    return AIAFramework()

@pytest.fixture
def runner():
    """Provides a Typer CliRunner."""
    return CliRunner()


class TestAIAFrameworkWithReasoning(unittest.TestCase):
    """
    Test cases for the Autonomous Intelligence Agent Framework,
    focusing on its integration with the Advanced Reasoning Engine.
    """

    @patch("chimera_intel.core.aia_framework.decompose_objective")
    def test_create_initial_plans_no_llm_fallback(self, mock_decompose):
        """
        Tests if the AIA correctly falls back to domain extraction when the LLM returns no tasks.
        """
        mock_decompose.return_value = []  # Simulate LLM failure
        console_mock = MagicMock()
        objective = "Analyze the security of example.com"

        plans = create_initial_plans(objective, console_mock)

        self.assertEqual(len(plans), 1)
        self.assertEqual(len(plans[0].tasks), 1)
        task = plans[0].tasks[0]
        self.assertEqual(task.module, "footprint")
        self.assertEqual(task.params, {"domain": "example.com"})
        console_mock.print.assert_called_with(
            "[yellow]Warning: Reasoning engine returned no tasks. Trying fallback analysis...[/]"
        )

    @patch("chimera_intel.core.aia_framework.generate_reasoning")
    def test_synthesize_and_refine_serialization_fallback(
        self, mock_generate_reasoning
    ):
        """
        Tests that synthesize_and_refine uses repr() for non-serializable results.
        """
        # A mock object that will raise a TypeError when serialized with json.dumps

        class NonSerializable:
            def __repr__(self):
                return "<NonSerializable object>"

        mock_generate_reasoning.return_value = ReasoningOutput(
            analytical_summary="Summary based on fallback.",
            hypotheses=[],
            recommendations=[],
            next_steps=[],
        )

        plan = Plan(
            objective="Test serialization fallback",
            tasks=[
                Task(
                    id="1",
                    module="footprint",
                    params={},
                    status="completed",
                    result=NonSerializable(),
                )
            ],
        )

        report, _ = synthesize_and_refine(plan, {})

        # Verify that the reasoning engine was called and the raw output used repr()

        mock_generate_reasoning.assert_called_once()
        self.assertIn("<NonSerializable object>", report.raw_outputs[0]["footprint"])



# A dummy async function to mock a module's run method
async def mock_module_run(params: dict):
    """A mock function to simulate a module's execution."""
    if params.get("domain") == "error.com":
        raise Exception("Mock module error")
    return AnalysisResult(
        module_name="mock_module",
        data={"domain": params.get("domain"), "status": "ok"}
    )

# A dummy class to mock a module

# --- AIAFramework Class Tests ---

def test_framework_initialization(framework):
    """Tests that the framework initializes with empty registries."""
    assert framework.modules == {}
    assert framework.module_aliases == {}

def test_register_module(framework):
    """Tests successful module registration."""
    mock_module = MockModule()
    framework.register_module(mock_module)
    assert "mock_module" in framework.modules
    assert framework.modules["mock_module"] == mock_module

def test_register_module_with_aliases(framework):
    """Tests module registration with aliases."""
    mock_module = MockModule()
    framework.register_module(mock_module, aliases=["mock", "m"])
    assert "mock_module" in framework.modules
    assert "mock" in framework.module_aliases
    assert "m" in framework.module_aliases
    assert framework.module_aliases["mock"] == "mock_module"

def test_register_module_duplicate(framework, caplog):
    """Tests that reregistering a module logs a warning."""
    mock_module_1 = MockModule(name="module1")
    mock_module_2 = MockModule(name="module1")
    
    framework.register_module(mock_module_1)
    framework.register_module(mock_module_2) # Attempt duplicate
    
    assert "Warning: Module 'module1' is already registered." in caplog.text

def test_register_module_duplicate_alias(framework, caplog):
    """Tests that reregistering an alias logs a warning."""
    mock_module_1 = MockModule(name="module1")
    mock_module_2 = MockModule(name="module2")
    
    framework.register_module(mock_module_1, aliases=["alias1"])
    framework.register_module(mock_module_2, aliases=["alias1"]) # Attempt duplicate alias
    
    assert "Warning: Alias 'alias1' is already registered" in caplog.text

def test_get_module_by_name(framework):
    """Tests retrieving a module by its primary name."""
    mock_module = MockModule()
    framework.register_module(mock_module)
    
    retrieved = framework.get_module("mock_module")
    assert retrieved == mock_module

def test_get_module_by_alias(framework):
    """Tests retrieving a module by one of its aliases."""
    mock_module = MockModule()
    framework.register_module(mock_module, aliases=["alias1"])
    
    retrieved = framework.get_module("alias1")
    assert retrieved == mock_module

def test_get_module_unknown(framework):
    """Tests that getting an unknown module returns None."""
    retrieved = framework.get_module("unknown_module")
    assert retrieved is None

@pytest.mark.asyncio
async def test_execute_task_async_success(framework):
    """Tests successful asynchronous task execution."""
    mock_module = MockModule()
    framework.register_module(mock_module)
    
    task = {"module": "mock_module", "params": {"domain": "example.com"}}
    result = await framework.execute_task_async(task)
    
    assert isinstance(result, AnalysisResult)
    assert result.module_name == "mock_module"
    assert result.data["status"] == "ok"
    # Check that the module's run method was called with the correct params
    mock_module.run.assert_called_once_with({"domain": "example.com"})

@pytest.mark.asyncio
async def test_execute_task_async_module_not_found(framework, caplog):
    """Tests executing a task for an unregistered module."""
    task = {"module": "unknown_module", "params": {}}
    result = await framework.execute_task_async(task)
    
    assert isinstance(result, AnalysisResult)
    assert result.module_name == "unknown_module"
    assert result.error == "Module 'unknown_module' not found."
    assert "Module 'unknown_module' not found" in caplog.text

@pytest.mark.asyncio
async def test_execute_task_async_module_exception(framework, caplog):
    """Tests when a module raises an exception during execution."""
    mock_module = MockModule()
    framework.register_module(mock_module)
    
    # The mock_module_run function is designed to throw an error for "error.com"
    task = {"module": "mock_module", "params": {"domain": "error.com"}}
    result = await framework.execute_task_async(task)
    
    assert isinstance(result, AnalysisResult)
    assert result.module_name == "mock_module"
    assert "Error executing module 'mock_module'" in result.error
    assert "Mock module error" in result.error
    assert "Error executing module 'mock_module'" in caplog.text

@pytest.mark.asyncio
@patch("chimera_intel.core.aia_framework.decompose_objective")
@patch("chimera_intel.core.aia_framework.generate_reasoning")
@patch("chimera_intel.core.aia_framework.GraphDB")
async def test_run_analysis_pipeline_success(mock_graphdb, mock_reasoning, mock_decompose, framework):
    """Tests a successful run of the analysis pipeline."""
    # 1. Mock decomposition
    initial_tasks = [{"module": "mock_module", "params": {"domain": "example.com"}}]
    mock_decompose.return_value = initial_tasks
    
    # 2. Register mock module
    mock_module = MockModule()
    framework.register_module(mock_module)
    
    # 3. Mock reasoning
    # First reasoning step: returns no new tasks, ending the loop
    mock_reasoning.return_value = ReasoningOutput(
        analytical_summary="Analysis complete.",
        next_steps=[] # Empty list stops the pipeline
    )
    
    # 4. Mock DB
    mock_db_instance = MagicMock()
    mock_db_instance.add_analysis_to_project = AsyncMock()
    mock_graphdb.return_value = mock_db_instance
    
    # Run the pipeline
    objective = "Analyze example.com"
    project_id = 1
    final_state = await framework.run_analysis_pipeline(objective, project_id)
    
    # Assertions
    mock_decompose.assert_called_once_with(objective) # Decomposed
    mock_module.run.assert_called_once_with({"domain": "example.com"}) # Module ran
    mock_reasoning.assert_called_once() # Reasoning ran
    
    assert final_state.project_id == project_id
    assert final_state.objective == objective
    assert len(final_state.results) == 1
    assert final_state.results[0].module_name == "mock_module"
    assert final_state.summary == "Analysis complete."
    assert final_state.status == "Completed"
    
    # Check that results were saved to DB
    mock_db_instance.add_analysis_to_project.assert_called_once()

@pytest.mark.asyncio
@patch("chimera_intel.core.aia_framework.decompose_objective")
@patch("chimera_intel.core.aia_framework.generate_reasoning")
@patch("chimera_intel.core.aia_framework.GraphDB")
async def test_run_analysis_pipeline_iterative(mock_graphdb, mock_reasoning, mock_decompose, framework):
    """Tests an iterative pipeline run (task -> reason -> new task -> reason -> stop)."""
    # 1. Mocks
    mock_db_instance = MagicMock()
    mock_db_instance.add_analysis_to_project = AsyncMock()
    mock_graphdb.return_value = mock_db_instance
    
    mock_module_1 = MockModule(name="module1")
    mock_module_2 = MockModule(name="module2")
    framework.register_module(mock_module_1)
    framework.register_module(mock_module_2)
    
    # 2. Setup mock returns
    mock_decompose.return_value = [{"module": "module1", "params": {"p": 1}}]
    
    # Mock reasoning to return a new task the first time, and stop the second time
    mock_reasoning.side_effect = [
        ReasoningOutput(
            analytical_summary="Step 1 complete.",
            next_steps=[{"module": "module2", "params": {"p": 2}}] # New task
        ),
        ReasoningOutput(
            analytical_summary="Step 2 complete.",
            next_steps=[] # Stop
        )
    ]
    
    # 3. Run
    final_state = await framework.run_analysis_pipeline("Iterative test", 1)
    
    # 4. Assertions
    assert mock_decompose.call_count == 1
    assert mock_module_1.run.call_count == 1
    assert mock_module_2.run.call_count == 1
    assert mock_reasoning.call_count == 2
    
    assert final_state.status == "Completed"
    assert final_state.summary == "Step 2 complete."
    assert len(final_state.results) == 2 # Both module results saved
    assert final_state.results[0].module_name == "module1"
    assert final_state.results[1].module_name == "module2"

@pytest.mark.asyncio
@patch("chimera_intel.core.aia_framework.decompose_objective")
@patch("chimera_intel.core.aia_framework.GraphDB")
async def test_run_analysis_pipeline_decomposition_fails(mock_graphdb, mock_decompose, framework):
    """Tests pipeline failure if decomposition returns no tasks."""
    mock_decompose.return_value = [] # No tasks
    mock_db_instance = MagicMock()
    mock_graphdb.return_value = mock_db_instance

    final_state = await framework.run_analysis_pipeline("Empty test", 1)
    
    assert final_state.status == "Failed"
    assert "Failed to decompose objective into initial tasks" in final_state.error
    assert mock_db_instance.add_analysis_to_project.assert_called_once # Should save failed state

@pytest.mark.asyncio
@patch("chimera_intel.core.aia_framework.decompose_objective")
@patch("chimera_intel.core.aia_framework.GraphDB")
async def test_run_analysis_pipeline_module_exec_fails(mock_graphdb, mock_decompose, framework):
    """Tests pipeline failure if a module execution fails."""
    # 1. Mocks
    mock_db_instance = MagicMock()
    mock_graphdb.return_value = mock_db_instance
    
    # Decompose returns a task for an unknown module
    mock_decompose.return_value = [{"module": "unknown_module", "params": {}}]
    
    # 2. Run
    final_state = await framework.run_analysis_pipeline("Module fail test", 1)
    
    # 3. Assertions
    assert final_state.status == "Failed"
    assert "Module 'unknown_module' not found." in final_state.error
    assert len(final_state.results) == 1 # The failed result
    assert final_state.results[0].error is not None
    assert mock_db_instance.add_analysis_to_project.call_count == 1 # Saves final failed state

@pytest.mark.asyncio
@patch("chimera_intel.core.aia_framework.decompose_objective")
@patch("chimera_intel.core.aia_framework.generate_reasoning")
@patch("chimera_intel.core.aia_framework.GraphDB")
async def test_run_analysis_pipeline_reasoning_fails(mock_graphdb, mock_reasoning, mock_decompose, framework):
    """Tests pipeline failure if reasoning fails."""
    # 1. Mocks
    mock_db_instance = MagicMock()
    mock_graphdb.return_value = mock_db_instance
    mock_module = MockModule()
    framework.register_module(mock_module)
    
    mock_decompose.return_value = [{"module": "mock_module", "params": {}}]
    mock_reasoning.side_effect = Exception("Mock reasoning error") # Reasoning fails
    
    # 2. Run
    final_state = await framework.run_analysis_pipeline("Reasoning fail test", 1)
    
    # 3. Assertions
    assert final_state.status == "Failed"
    assert "Error during reasoning step: Mock reasoning error" in final_state.error
    assert len(final_state.results) == 1 # The one successful module run
    assert final_state.results[0].error is None
    assert mock_db_instance.add_analysis_to_project.call_count == 1 # Saves final failed state

# --- CLI Tests ---

@patch("chimera_intel.core.aia_framework.AIAFramework.run_analysis_pipeline", new_callable=AsyncMock)
def test_cli_analyze_success(mock_run_pipeline, runner):
    """Tests the 'analyze' CLI command on success."""
    # Mock the pipeline to return a successful state
    mock_state = MagicMock()
    mock_state.status = "Completed"
    mock_state.summary = "CLI analysis complete."
    mock_state.error = None
    mock_state.results = [AnalysisResult(module_name="test", data={})]
    mock_run_pipeline.return_value = mock_state
    
    result = runner.invoke(aia_cli_app, ["analyze", "1", "Test objective"])
    
    assert result.exit_code == 0
    assert "Analysis complete." in result.stdout
    assert "Status: Completed" in result.stdout
    assert "Summary: CLI analysis complete." in result.stdout
    mock_run_pipeline.assert_called_once_with("Test objective", 1)

@patch("chimera_intel.core.aia_framework.AIAFramework.run_analysis_pipeline", new_callable=AsyncMock)
def test_cli_analyze_failure(mock_run_pipeline, runner):
    """Tests the 'analyze' CLI command on failure."""
    # Mock the pipeline to return a failed state
    mock_state = MagicMock()
    mock_state.status = "Failed"
    mock_state.summary = ""
    mock_state.error = "A mock error occurred"
    mock_state.results = []
    mock_run_pipeline.return_value = mock_state
    
    result = runner.invoke(aia_cli_app, ["analyze", "1", "Test objective"])
    
    assert result.exit_code == 1 # Should exit with error
    assert "Analysis failed." in result.stdout
    assert "Status: Failed" in result.stdout
    assert "Error: A mock error occurred" in result.stdout

def test_cli_list_modules_success(runner):
    """Tests the 'list-modules' CLI command."""
    # This command doesn't use the framework instance, so no patching needed
    result = runner.invoke(aia_cli_app, ["list-modules"])
    
    assert result.exit_code == 0
    # Check for some of the hardcoded modules in the command's output
    assert "footprint" in result.stdout
    assert "threat_intel" in result.stdout
    assert "vulnerability_scanner" in result.stdout

if __name__ == "__main__":
    unittest.main()
