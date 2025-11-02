import pytest
from typer.testing import CliRunner, typer
from datetime import datetime

# Import the schemas needed to build a mock result
from src.chimera_intel.core.schemas import (
    DataFusionResult,
    MasterEntityProfile,
    PatternOfLife,
    PatternOfLifeEvent,
    CognitivePrediction,
    PhysicalLocation,
    SocialProfile,
)

# We test the plugin's app directly for isolation
try:
    from plugins.chimera_fusion.src.chimera_fusion.main import (
        plugin as fusion_plugin,
    )
except ImportError:
    pytest.skip(
        "Fusion plugin not found. Run 'pip install -e plugins/chimera_fusion'",
        allow_module_level=True,
    )


runner = CliRunner()


@pytest.fixture
def mock_fusion_result():
    """
    Creates a rich, mock DataFusionResult object, similar to what the
    real _run_fusion_analysis function would produce.
    """
    profile = MasterEntityProfile(
        entity_id="entity-mock-123",
        primary_name="Mock Target",
        aliases=["mock-alias", "target-x"],
        linked_cyber_indicators=["1.2.3.4", "mock@example.com"],
        linked_physical_locations=[
            PhysicalLocation(
                name="Mock Location",
                address="123 Mockingbird Lane",
                latitude=40.7128,
                longitude=-74.0060,
            )
        ],
        linked_social_profiles=[
            SocialProfile(name="MockSocial", url="http://mock.com/profile")
        ],
        resolved_from_fragments=["CYBINT:Mock", "SOCMINT:Mock", "LEGINT:Mock"],
    )

    pol = PatternOfLife(
        total_events=1,
        events=[
            PatternOfLifeEvent(
                timestamp=datetime(2025, 1, 1, 12, 0, 0),
                event_type="MOCK",
                summary="A mock event occurred.",
                source_data={"id": "mock-event-1"},
            )
        ],
        ai_summary="This is a mock AI-generated Pattern of Life summary.",
    )

    preds = [
        CognitivePrediction(
            prediction_text="This is a mock prediction about a future event.",
            confidence=0.85,
            justification="Based on correlated mock data points.",
            tactic="Predictive",
        )
    ]

    return DataFusionResult(
        target_identifier="test-target",
        master_entity_profile=profile,
        pattern_of_life=pol,
        predictions=preds,
        error=None,
    )


def test_fusion_plugin_loads():
    """Test that the plugin itself loads."""
    assert fusion_plugin.name == "fusion"
    assert isinstance(fusion_plugin.app, typer.Typer)


def test_fusion_run_command_mocked(mocker, mock_fusion_result):
    """
    Test the 'chimera fusion run <target>' command by mocking the
    heavy-lifting analysis function `_run_fusion_analysis`.
    """
    # We patch the function *where it is imported* in the fusion.py module
    mock_run_analysis = mocker.patch(
        "src.chimera_intel.core.fusion._run_fusion_analysis",
        return_value=mock_fusion_result,
    )

    # Run the CLI command via the plugin's app
    result = runner.invoke(fusion_plugin.app, ["run", "test-target"])

    # 1. Check exit code
    assert result.exit_code == 0

    # 2. Check that our mocked analysis function was called correctly
    mock_run_analysis.assert_called_once_with("test-target")

    # 3. Check that the output contains all the mock data we provided
    assert "--- 4D Fusion Analysis Report for: test-target ---" in result.stdout
    # Check Profile data
    assert "Master Entity Profile (entity-mock-123)" in result.stdout
    assert "1.2.3.4" in result.stdout
    assert "http://mock.com/profile" in result.stdout
    assert "CYBINT:Mock" in result.stdout
    # Check PoL data
    assert "Pattern of Life (4D)" in result.stdout
    assert "This is a mock AI-generated Pattern of Life summary." in result.stdout
    assert "[MOCK] A mock event occurred." in result.stdout
    # Check Prediction data
    assert "Predictive & Cognitive Modeling" in result.stdout
    assert "This is a mock prediction about a future event." in result.stdout
    assert "Confidence: 85.0%" in result.stdout
    assert "Tactic: Predictive" in result.stdout


def test_fusion_run_no_args():
    """Test that 'chimera fusion run' without a target asks for one."""
    result = runner.invoke(fusion_plugin.app, ["run"])
    assert result.exit_code != 0
    # Typer's default error message for a missing argument
    assert "Missing argument 'TARGET'" in result.stdout


def test_fusion_run_handles_error(mocker):
    """
    Test that the CLI correctly reports an error if the
    analysis function returns an error message.
    """
    # Create a mock result that only contains an error
    mock_error_result = DataFusionResult(
        target_identifier="test-target", error="A mock error occurred."
    )

    # Patch the analysis function to return the error
    mock_run_analysis = mocker.patch(
        "src.chimera_intel.core.fusion._run_fusion_analysis",
        return_value=mock_error_result,
    )

    result = runner.invoke(fusion_plugin.app, ["run", "test-target"])

    # 1. Check for a non-zero exit code
    assert result.exit_code == 1

    # 2. Check that the analysis function was still called
    mock_run_analysis.assert_called_once_with("test-target")

    # 3. Check that the error message is printed to the console
    assert "Error: A mock error occurred." in result.stdout
    assert "--- 4D Fusion Analysis Report ---" not in result.stdout