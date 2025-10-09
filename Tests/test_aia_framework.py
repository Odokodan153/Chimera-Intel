import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add the project's root directory to the Python path to ensure imports work correctly

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from chimera_intel.core.advanced_reasoning_engine import (
    decompose_objective,
    generate_reasoning,
    AnalysisResult,
    Hypothesis,
    Recommendation,
    ReasoningOutput,
)
from chimera_intel.core.aia_framework import (
    create_initial_plans,
    synthesize_and_refine,
    Plan,
    Task,
)
from chimera_intel.core.schemas import FootprintResult, ThreatIntelResult


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


if __name__ == "__main__":
    unittest.main()
