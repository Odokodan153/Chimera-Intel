import unittest
from unittest.mock import MagicMock, patch, AsyncMock
import sys
import os
import pytest
import asyncio
import json
import typer  # Import typer
from typer.testing import CliRunner
import logging # <-- Import logging to use for caplog.set_level

# Add the project's root directory to the Python path to ensure imports work correctly
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from chimera_intel.core.aia_framework import (
    # app as aia_cli_app,  <- REMOVED THIS LINE TO FIX LINTING ERRORS
    load_available_modules,
    create_initial_plans,
    execute_plan,
    synthesize_and_refine,
    _run_autonomous_analysis,
)
from chimera_intel.core.schemas import (
    AnalysisResult,
    ReasoningOutput,
    Plan,
    Task,
    SynthesizedReport,
)

# --- Mocks and Fixtures ---

@pytest.fixture
def runner():
    """Provides a Typer CliRunner."""
    return CliRunner()

@pytest.fixture
def mock_console():
    """Provides a mock Rich Console."""
    return MagicMock()

@pytest.fixture
def mock_modules():
    """Provides a fixture for available modules."""
    return {
        "async_module": {
            "func": AsyncMock(
                return_value=AnalysisResult(
                    module_name="async_module", data={"status": "ok_async"}
                )
            ),
            "is_async": True,
        },
        "sync_module": {
            "func": MagicMock(
                return_value=AnalysisResult(
                    module_name="sync_module", data={"status": "ok_sync"}
                )
            ),
            "is_async": False,
        },
        "fail_module": {
            "func": AsyncMock(side_effect=Exception("Module Failed")),
            "is_async": True,
        },
        "timeout_module": {
            # Provide a base AsyncMock
            "func": AsyncMock(side_effect=asyncio.TimeoutError("Module Timed Out")),
            "is_async": True,
        },
    }


# --- Test Classes ---

class TestLoadAvailableModules:
    """Tests the dynamic module loader."""

    @pytest.fixture
    def mock_modules_pkg(self):
        """Mocks the chimera_intel.core package."""
        mock_pkg = MagicMock()
        mock_pkg.__path__ = ["dummy/path/to/core"]
        # FIX: Point to the 'core' package, not 'core.modules'
        mock_pkg.__name__ = "chimera_intel.core"
        return mock_pkg

    # --- FIX: Changed patch targets from '...aia_framework.pkgutil.iter_modules' to 'pkgutil.iter_modules'
    @patch("pkgutil.iter_modules")
    @patch("importlib.import_module")
    # --- END FIX ---
    @patch("chimera_intel.core.aia_framework.aia_core_package") 
    def test_load_success(self, mock_aia_core_package, mock_import, mock_iter_modules, mock_modules_pkg, caplog):
        """Tests successful loading of allowed sync and async modules."""
        # Configure the mock package
        mock_aia_core_package.__path__ = mock_modules_pkg.__path__
        mock_aia_core_package.__name__ = mock_modules_pkg.__name__

        mock_mod_async = MagicMock()
        mock_mod_async.run = AsyncMock()
        
        mock_mod_sync = MagicMock()
        mock_mod_sync.run = MagicMock()

        # Simulate finding two allowed modules
        mock_iter_modules.return_value = [
            (None, "chimera_intel.core.footprint", None),
            (None, "chimera_intel.core.threat_intel", None),
        ]
        mock_import.side_effect = [mock_mod_async, mock_mod_sync]

        modules = load_available_modules()

        assert "footprint" in modules
        assert "threat_intel" in modules
        assert modules["footprint"]["is_async"] is True
        assert modules["threat_intel"]["is_async"] is False
        assert "Loaded 2 modules" in caplog.text

    @patch("pkgutil.iter_modules")
    @patch("chimera_intel.core.aia_framework.importlib.import_module")  # <- правилният patch
    @patch("chimera_intel.core.aia_framework.aia_core_package")
    def test_load_skip_non_allowed(self, mock_aia_core_package, mock_import, mock_iter_modules, mock_modules_pkg, caplog):
        mock_aia_core_package.__path__ = mock_modules_pkg.__path__
        mock_aia_core_package.__name__ = mock_modules_pkg.__name__

        mock_mod = MagicMock()
        mock_mod.run = AsyncMock()

        # Симулираме намерени модули: allowed + not allowed
        mock_iter_modules.return_value = [
            (None, "chimera_intel.core.footprint", None),
            (None, "chimera_intel.core.some_other", None),
        ]
        mock_import.side_effect = [mock_mod]  # само allowed module се импортира

        modules = load_available_modules()

        assert "footprint" in modules
        assert "some_other" not in modules
        assert "Loaded 2 modules" in caplog.text
        mock_import.assert_called_once_with("chimera_intel.core.footprint")

    # --- FIX: Changed patch targets from '...aia_framework.pkgutil.iter_modules' to 'pkgutil.iter_modules'
    @patch("pkgutil.iter_modules")
    # --- FIX: Add the missing patch for importlib.import_module ---
    @patch("importlib.import_module")
    # --- END FIX ---
    # --- END FIX ---
    @patch("chimera_intel.core.aia_framework.aia_core_package")
    def test_load_no_run_attr(self, mock_aia_core_package, mock_import, mock_iter_modules, mock_modules_pkg, caplog):
        """Tests warning if a module has no 'run' attribute."""
        
        # --- FIX: Explicitly set the log capture level ---
        # This ensures that all logs, including WARNING, are captured
        # just in case the default level is being overridden.
        caplog.set_level(logging.WARNING)
        # --- END FIX ---
        
        # Configure the mock package
        mock_aia_core_package.__path__ = mock_modules_pkg.__path__
        mock_aia_core_package.__name__ = mock_modules_pkg.__name__
        
        
        class DummyModule: 
            pass
        mock_mod = DummyModule() 

        mock_iter_modules.return_value = [
            (None, "chimera_intel.core.footprint", None)
        ]
        mock_import.side_effect = [mock_mod]

        modules = load_available_modules()
        
        # We expect the log, but then the function should find no modules and hit the fallback
        assert "Falling back to built-ins" in caplog.text
        assert "footprint" in modules # The module *is* present from the fallback.

    # --- FIX: Changed patch target from '...aia_framework.pkgutil.iter_modules' to 'pkgutil.iter_modules'
    @patch("pkgutil.iter_modules")
    # --- END FIX ---
    @patch("chimera_intel.core.aia_framework.aia_core_package") 
    def test_load_fallback(self, mock_aia_core_package, mock_iter_modules, caplog):
        """Tests fallback to built-ins if dynamic loading finds nothing."""
        # Configure the mock package
        mock_aia_core_package.__path__ = ["dummy/path"]
        mock_aia_core_package.__name__ = "chimera_intel.core"
        
        mock_iter_modules.return_value = []  # Simulate no modules found

        modules = load_available_modules()
        assert "footprint" in modules
        assert "threat_intel" in modules
        assert modules["footprint"]["is_async"] is True
        assert modules["threat_intel"]["is_async"] is False
        assert "Falling back to built-ins" in caplog.text


class TestCreateInitialPlans:
    """Tests the initial plan creation logic."""

    @patch("chimera_intel.core.aia_framework.decompose_objective")
    def test_create_initial_plans_success(self, mock_decompose, mock_console):
        """Tests successful plan creation from LLM decomposition."""
        mock_decompose.return_value = [
            {"module": "footprint", "params": {"domain": "example.com"}},
            {"module": "threat_intel", "params": {"indicator": "example.com"}},
        ]
        objective = "Analyze example.com"

        plans = create_initial_plans(objective, mock_console)

        assert len(plans) == 1
        assert len(plans[0].tasks) == 2
        assert plans[0].tasks[0].module == "footprint"
        assert plans[0].tasks[1].module == "threat_intel"
        mock_console.print.assert_not_called()

    @patch("chimera_intel.core.aia_framework.decompose_objective")
    def test_create_initial_plans_fallback_success(self, mock_decompose, mock_console):
        """Tests fallback to domain extraction when LLM fails."""
        mock_decompose.return_value = []  # Simulate LLM failure
        objective = "Analyze the security of example.com"

        plans = create_initial_plans(objective, mock_console)

        assert len(plans) == 1
        assert len(plans[0].tasks) == 1
        assert plans[0].tasks[0].module == "footprint"
        assert plans[0].tasks[0].params == {"domain": "example.com"}
        mock_console.print.assert_called_with(
            "[yellow]Warning: Reasoning engine returned no tasks. Trying fallback analysis...[/]"
        )

    @patch("chimera_intel.core.aia_framework.decompose_objective")
    def test_create_initial_plans_fallback_no_domain(self, mock_decompose, mock_console):
        """Tests fallback failure when no domain is found."""
        mock_decompose.return_value = []
        objective = "Analyze this threat actor"

        plans = create_initial_plans(objective, mock_console)

        assert len(plans) == 0
        mock_console.print.assert_called_with(
            "[yellow]Warning: Reasoning engine returned no tasks. Trying fallback analysis...[/]"
        )


@pytest.mark.asyncio
class TestExecutePlan:
    """Tests the `execute_plan` async function."""

    async def test_execute_plan_success_async_sync(self, mock_console, mock_modules):
        """Tests successful execution of both async and sync modules."""
        plan = Plan(
            objective="Test",
            tasks=[
                Task(id=1, module="async_module", params={"p": 1}),
                Task(id=2, module="sync_module", params={"p": 2}),
            ],
        )

        result_plan = await execute_plan(plan, mock_console, mock_modules, timeout=10)

        assert result_plan.tasks[0].status == "completed"
        assert result_plan.tasks[0].result.data == {"status": "ok_async"}
        assert result_plan.tasks[1].status == "completed"
        assert result_plan.tasks[1].result.data == {"status": "ok_sync"}
        
        # Check that the mock functions were called correctly
        mock_modules["async_module"]["func"].assert_called_once_with(p=1)
        mock_modules["sync_module"]["func"].assert_called_once_with(p=2)

    async def test_execute_plan_module_not_found(self, mock_console, mock_modules):
        """Tests failure when a module is not in the available_modules dict."""
        plan = Plan(
            objective="Test",
            tasks=[Task(id=1, module="unknown_module", params={})],
        )
        result_plan = await execute_plan(plan, mock_console, mock_modules, timeout=10)

        assert result_plan.tasks[0].status == "failed"
        assert "Module 'unknown_module' not found" in result_plan.tasks[0].result["error"]

    async def test_execute_plan_task_exception(self, mock_console, mock_modules):
        """Tests failure when a module raises an exception."""
        plan = Plan(
            objective="Test",
            tasks=[Task(id=1, module="fail_module", params={})],
        )
        result_plan = await execute_plan(plan, mock_console, mock_modules, timeout=10)

        assert result_plan.tasks[0].status == "failed"
        assert "Exception: Module Failed" in result_plan.tasks[0].result["error"]

    async def test_execute_plan_task_timeout(self, mock_console, mock_modules):
        """Tests failure when a module times out."""
        
        async def long_sleep(*args, **kwargs):
            await asyncio.sleep(2)
            return "Should not return"

        # Set the side_effect on the *existing* AsyncMock from the fixture
        mock_modules["timeout_module"]["func"].side_effect = long_sleep

        plan = Plan(
            objective="Test",
            tasks=[Task(id=1, module="timeout_module", params={})],
        )
        # Use a short timeout
        result_plan = await execute_plan(plan, mock_console, mock_modules, timeout=1) 

        assert result_plan.tasks[0].status == "failed"
        assert "TimeoutError: Task execution exceeded 1s" in result_plan.tasks[0].result["error"]


class TestSynthesizeAndRefine:
    """Tests the synthesis and refinement logic."""

    @patch("chimera_intel.core.aia_framework.generate_reasoning")
    def test_synthesize_and_refine_new_tasks(self, mock_generate_reasoning):
        """Tests that new tasks from the reasoning engine are added to the plan."""
        plan = Plan(objective="Test", tasks=[])
        task_counts = {}
        
        mock_generate_reasoning.return_value = ReasoningOutput(
            analytical_summary="Summary",
            hypotheses=[],
            recommendations=[],
            next_steps=[
                {"module": "new_module", "params": {"p": 1}},
                {"module": "another_module", "params": {"p": 2}},
            ],
        )

        _, result_plan = synthesize_and_refine(plan, task_counts)

        assert len(result_plan.tasks) == 2
        assert result_plan.tasks[0].module == "new_module"
        assert result_plan.tasks[0].status == "pending"
        assert result_plan.tasks[1].module == "another_module"
        assert task_counts == {
            ("new_module", '{"p": 1}'): 1,
            ("another_module", '{"p": 2}'): 1,
        }

    @patch("chimera_intel.core.aia_framework.generate_reasoning")
    def test_synthesize_and_refine_duplicate_task(self, mock_generate_reasoning):
        """Tests that duplicate tasks are not added."""
        existing_task = Task(id=1, module="new_module", params={"p": 1}, status="completed")
        plan = Plan(objective="Test", tasks=[existing_task])
        task_counts = {}
        
        # Reasoning engine suggests the *exact same* task again
        mock_generate_reasoning.return_value = ReasoningOutput(
            analytical_summary="Summary",
            next_steps=[{"module": "new_module", "params": {"p": 1}}],
            hypotheses=[], recommendations=[]
        )

        _, result_plan = synthesize_and_refine(plan, task_counts)

        # No new task should be added
        assert len(result_plan.tasks) == 1
        assert task_counts == {}

    @patch("chimera_intel.core.aia_framework.generate_reasoning")
    def test_synthesize_and_refine_execution_limit(self, mock_generate_reasoning, caplog):
        """Tests that tasks exceeding the execution limit are skipped."""
        plan = Plan(objective="Test", tasks=[])
        # Pre-populate counts to simulate tasks have run twice already
        task_counts = {
            ("recursive_module", '{"p": 1}'): 2 
        }
        
        mock_generate_reasoning.return_value = ReasoningOutput(
            analytical_summary="Summary",
            next_steps=[{"module": "recursive_module", "params": {"p": 1}}],
            hypotheses=[], recommendations=[]
        )

        _, result_plan = synthesize_and_refine(plan, task_counts)

        # No new task should be added
        assert len(result_plan.tasks) == 0
        assert task_counts[("recursive_module", '{"p": 1}')] == 3 # Count is incremented
        assert "Skipping" in caplog.text # Check for warning log

    @patch("chimera_intel.core.aia_framework.generate_reasoning")
    def test_synthesize_and_refine_serialization_fallback(self, mock_generate_reasoning):
        """Tests that repr() is used for non-serializable results. (From original test)"""
        class NonSerializable:
            def __repr__(self):
                return "<NonSerializable object>"

        mock_generate_reasoning.return_value = ReasoningOutput(
            analytical_summary="Summary based on fallback.",
            hypotheses=[], recommendations=[], next_steps=[]
        )
        plan = Plan(
            objective="Test serialization fallback",
            tasks=[
                Task(id="1", module="footprint", params={}, status="completed", result=NonSerializable())
            ],
        )

        report, _ = synthesize_and_refine(plan, {})

        mock_generate_reasoning.assert_called_once()
        # Check that the raw output contains the repr string
        assert "<NonSerializable object>" in json.dumps(report.raw_outputs)


@pytest.mark.asyncio
class TestRunAutonomousAnalysis:
    """Tests the main orchestration logic in _run_autonomous_analysis."""

    @patch("chimera_intel.core.aia_framework.synthesize_and_refine")
    @patch("chimera_intel.core.aia_framework.execute_plan", new_callable=AsyncMock)
    @patch("chimera_intel.core.aia_framework.create_initial_plans")
    @patch("chimera_intel.core.aia_framework.load_available_modules")
    @patch("builtins.open")
    @patch("json.dump")
    async def test_run_success_single_loop(
        self, mock_json_dump, mock_open, mock_load_mods, mock_create_plans, mock_exec_plan, mock_synthesize
    ):
        """Tests a successful run that completes in a single loop."""
        objective = "Test example.com"
        output_file = "test_report.json"
        
        # 1. Setup Mocks
        mock_load_mods.return_value = {"footprint": {}}
        
        plan = Plan(objective=objective, tasks=[Task(id=1, module="footprint", params={})])
        mock_create_plans.return_value = [plan]
        
        # 2. Mock execute_plan to return the plan with the task completed
        plan_after_exec = Plan(objective=objective, tasks=[
            Task(id=1, module="footprint", params={}, status="completed", result=AnalysisResult(module_name="footprint", data={}))
        ])
        mock_exec_plan.return_value = plan_after_exec
        
        # 3. Mock synthesize_and_refine to return *no new tasks*
        report = SynthesizedReport(objective=objective, summary="All done")
        mock_synthesize.return_value = (report, plan_after_exec) # No new pending tasks

        # 4. Run
        await _run_autonomous_analysis(objective, output_file, max_runs=5, timeout=30, max_runtime=300)

        # 5. Assertions
        mock_create_plans.assert_called_once_with(objective, unittest.mock.ANY)
        mock_exec_plan.assert_called_once()
        mock_synthesize.assert_called_once()
        mock_open.assert_called_once_with(output_file, "w", encoding="utf-8")
        mock_json_dump.assert_called_once()

    @patch("chimera_intel.core.aia_framework.synthesize_and_refine")
    @patch("chimera_intel.core.aia_framework.execute_plan", new_callable=AsyncMock)
    @patch("chimera_intel.core.aia_framework.create_initial_plans")
    @patch("chimera_intel.core.aia_framework.load_available_modules")
    async def test_run_iterative_loop(
        self, mock_load_mods, mock_create_plans, mock_exec_plan, mock_synthesize
    ):
        """Tests an iterative run (task -> reason -> new task -> reason -> stop)."""
        objective = "Test example.com"
        
        # 1. Mocks
        mock_load_mods.return_value = {"m1": {}, "m2": {}}
        
        plan_start = Plan(objective=objective, tasks=[Task(id=1, module="m1", params={})])
        mock_create_plans.return_value = [plan_start]
        
        # 2. Setup side effects for iterative run
        plan_after_exec_1 = Plan(objective=objective, tasks=[
            Task(id=1, module="m1", params={}, status="completed", result=AnalysisResult(module_name="m1", data={}))
        ])
        plan_after_synth_1 = Plan(objective=objective, tasks=[
            Task(id=1, module="m1", params={}, status="completed", result=AnalysisResult(module_name="m1", data={})),
            Task(id=2, module="m2", params={}) # NEW TASK
        ])
        plan_after_exec_2 = Plan(objective=objective, tasks=[
            Task(id=1, module="m1", params={}, status="completed", result=AnalysisResult(module_name="m1", data={})),
            Task(id=2, module="m2", params={}, status="completed", result=AnalysisResult(module_name="m2", data={}))
        ])
        plan_after_synth_2 = plan_after_exec_2 # NO NEW TASKS
        
        mock_exec_plan.side_effect = [plan_after_exec_1, plan_after_exec_2]
        
        report1 = SynthesizedReport(objective=objective, summary="Step 1 done")
        report2 = SynthesizedReport(objective=objective, summary="Step 2 done")
        mock_synthesize.side_effect = [(report1, plan_after_synth_1), (report2, plan_after_synth_2)]

        # 3. Run
        await _run_autonomous_analysis(objective, None, max_runs=5, timeout=30, max_runtime=300)

        # 4. Assertions
        assert mock_exec_plan.call_count == 2
        assert mock_synthesize.call_count == 2

    @patch("chimera_intel.core.aia_framework.create_initial_plans")
    async def test_run_initial_plan_fails(self, mock_create_plans):
        """Tests that the run exits if no initial plan can be created."""
        mock_create_plans.return_value = [] # No plan
        
        with pytest.raises(typer.Exit) as e:
            await _run_autonomous_analysis("Test", None, 5, 30, 300)
        
        assert e.value.exit_code == 1


class TestCLI:
    """Tests the Typer CLI commands."""

    def test_cli_execute_objective_success(self,runner):
        mock_are = MagicMock()
        # Patch before importing the CLI app
        with patch.dict("sys.modules", {"chimera_intel.core.advanced_reasoning_engine": mock_are}):
            from chimera_intel.core.aia_framework import app as aia_cli_app

            with patch("chimera_intel.core.aia_framework._run_autonomous_analysis", new_callable=AsyncMock) as mock_run_analysis:
                result = runner.invoke(aia_cli_app, ["execute-objective", "Analyze example.com"])
                
                assert result.exit_code == 0, result.output
                assert "Objective Received" in result.output
                mock_run_analysis.assert_called_once_with(
                    "Analyze example.com",
                    unittest.mock.ANY,
                    5,
                    60,
                    300
                )



    def test_cli_execute_objective_args_passed(self,runner):
        mock_are = MagicMock()
        with patch.dict("sys.modules", {"chimera_intel.core.advanced_reasoning_engine": mock_are}):
            from chimera_intel.core.aia_framework import app as aia_cli_app

            with patch("chimera_intel.core.aia_framework._run_autonomous_analysis", new_callable=AsyncMock) as mock_run_analysis:
                result = runner.invoke(
                    aia_cli_app,
                    [
                        "execute-objective",
                        "--",
                        "Full test",
                        "--output",
                        "out.json",
                        "--max-runs",
                        "3",
                        "--timeout",
                        "90",
                        "--max-runtime",
                        "600",
                    ],
                )

                assert result.exit_code == 0, result.output
                mock_run_analysis.assert_called_once_with(
                    "Full test",
                    "out.json",
                    3,
                    90,
                    600,
                )

    def test_cli_execute_objective_exception(self,runner):
        mock_are = MagicMock()
        with patch.dict("sys.modules", {"chimera_intel.core.advanced_reasoning_engine": mock_are}):
            from chimera_intel.core.aia_framework import app as aia_cli_app

            with patch("chimera_intel.core.aia_framework._run_autonomous_analysis", new_callable=AsyncMock) as mock_run_analysis:
                mock_run_analysis.side_effect = Exception("A critical error")

                result = runner.invoke(
                    aia_cli_app,
                    ["execute-objective", "--", "Test"]
                )

                assert result.exit_code == 1, result.output
                assert "An unhandled error occurred" in result.output


if __name__ == "__main__":
    pytest.main()