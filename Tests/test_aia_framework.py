import unittest
import asyncio
from unittest.mock import MagicMock, patch

# Import the new advanced reasoning components

from chimera_intel.core.advanced_reasoning_engine import (
    decompose_objective,
    generate_reasoning,
    AnalysisResult,
    Hypothesis,
    Recommendation,
)

# Import the AIA components to test their integration

from chimera_intel.core.aia_framework import (
    create_initial_plans,
    synthesize_and_refine,
    Plan,
    Task,
)

# Mock data from other modules for controlled testing

from chimera_intel.core.schemas import FootprintResult, Vulnerability, ThreatIntelResult


class TestAIAFrameworkWithReasoning(unittest.TestCase):
    """
    Test cases for the Autonomous Intelligence Agent Framework,
    focusing on its integration with the Advanced Reasoning Engine.
    """

    def test_decompose_complex_objective(self):
        """
        Tests if the Advanced Reasoning Engine correctly breaks down a complex objective.
        """
        complex_objective = "Assess the security posture of example.com and propose mitigation measures."
        sub_objectives = decompose_objective(complex_objective)
        self.assertEqual(len(sub_objectives), 2)
        self.assertIn("Assess", sub_objectives[0])
        self.assertIn("propose measures", sub_objectives[1].lower())

    def test_reasoning_engine_generates_hypotheses_and_recommendations(self):
        """
        Tests if the reasoning engine correctly generates hypotheses and recommendations
        from critical intelligence findings.
        """
        analysis_results = [
            AnalysisResult(
                module_name="threat_intel",
                data=ThreatIntelResult(indicator="CVE-2023-1234", is_malicious=True),
            )
        ]
        reasoning_output = generate_reasoning(
            "Assess vulnerabilities", analysis_results
        )
        self.assertEqual(len(reasoning_output.hypotheses), 1)
        self.assertEqual(len(reasoning_output.recommendations), 1)
        self.assertIn("Immediately patch", reasoning_output.recommendations[0].action)
        self.assertEqual(reasoning_output.recommendations[0].priority, "High")

    def test_aia_creates_multiple_plans_for_complex_objective(self):
        """
        Tests if the AIA correctly creates a multi-step plan when given a complex objective.
        """
        complex_objective = (
            "Assess the security posture of example.com and propose measures."
        )
        plans = create_initial_plans(complex_objective)
        # It should create one actionable plan for the assessment part

        self.assertEqual(len(plans), 1)
        self.assertIn("Assess", plans[0].objective)

    @patch("chimera_intel.core.aia_framework.generate_reasoning")
    def test_synthesize_and_refine_integrates_reasoning_output(
        self, mock_generate_reasoning
    ):
        """
        Tests that the main AIA loop correctly calls the reasoning engine and
        integrates its analytical summary, hypotheses, and recommendations.
        """
        # Configure the mock to return a rich reasoning output

        mock_generate_reasoning.return_value = MagicMock(
            analytical_summary="This is a reasoned summary.",
            hypotheses=[
                Hypothesis(statement="The target is likely vulnerable.", confidence=0.8)
            ],
            recommendations=[
                Recommendation(action="Patch immediately.", priority="High")
            ],
            next_steps=[],
        )

        # Create a plan with a single completed task to trigger synthesis

        plan = Plan(
            objective="Assess security of example.com",
            tasks=[
                Task(
                    id=1,
                    module="footprint",
                    params={},
                    status="completed",
                    result=FootprintResult(),
                )
            ],
        )

        report, _ = synthesize_and_refine(plan)

        # Verify that the report contains the data from the reasoning engine

        self.assertEqual(report.summary, "This is a reasoned summary.")
        self.assertEqual(len(report.hypotheses), 1)
        self.assertEqual(report.recommendations[0].action, "Patch immediately.")
        # Ensure the mock was called, confirming the integration

        mock_generate_reasoning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
