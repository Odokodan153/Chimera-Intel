import unittest
from chimera_intel.core.metacognition import (
    analyze_performance,
    generate_optimizations,
    identify_gaps,
    OperationLog,
)


class TestMetacognition(unittest.TestCase):
    """Test cases for the Metacognition & Self-Improving AI Core."""

    def setUp(self):
        """Set up a sample log for testing."""
        self.logs = [
            OperationLog(
                module_name="GEOINT",
                success=True,
                resource_cost=10,
                intelligence_tags=["location"],
            ),
            OperationLog(
                module_name="GEOINT",
                success=False,
                resource_cost=5,
                intelligence_tags=[],
            ),
            OperationLog(
                module_name="FININT",
                success=True,
                resource_cost=50,
                intelligence_tags=["finance"],
            ),
            OperationLog(
                module_name="FININT",
                success=True,
                resource_cost=60,
                intelligence_tags=["finance"],
            ),
        ]

    def test_analyze_performance(self):
        """Tests the performance analysis logic."""
        performance = analyze_performance(self.logs)
        self.assertEqual(len(performance), 2)
        # GEOINT: 50% success, avg cost 7.5, efficiency ~6
        # FININT: 100% success, avg cost 55, efficiency ~1.7

        self.assertEqual(
            performance[0].module_name, "GEOINT"
        )  # GEOINT is more efficient
        self.assertAlmostEqual(performance[0].success_rate, 50.0)
        self.assertAlmostEqual(performance[1].success_rate, 100.0)

    def test_generate_optimizations(self):
        """Tests the recommendation generation logic."""
        performance = analyze_performance(self.logs)
        optimizations = generate_optimizations(performance)
        # It should recommend deprioritizing the less efficient module (FININT)

        self.assertEqual(len(optimizations), 1)
        self.assertIn(
            "Deprioritize or re-evaluate the 'FININT' module",
            optimizations[0].recommendation,
        )

    def test_identify_gaps(self):
        """Tests the intelligence gap identification logic."""
        required_intel = ["location", "political", "finance"]
        gaps = identify_gaps(self.logs, required_intel)
        self.assertEqual(len(gaps), 1)
        self.assertIn("political", gaps[0].gap_description)
        self.assertIn("political", gaps[0].generated_collection_requirement)


if __name__ == "__main__":
    unittest.main()
