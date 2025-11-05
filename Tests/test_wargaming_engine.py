import pytest
import numpy as np
from src.chimera_intel.core.wargaming_engine import WargamingEngine, ScenarioInput, SimulationResult, ImpactMetrics

@pytest.fixture
def engine():
    """Provides a fresh instance of the WargamingEngine for each test."""
    return WargamingEngine()

def test_engine_initialization(engine):
    """Test that the engine initializes correctly."""
    assert engine is not None
    assert 'supply_chain_model' in engine.domain_models
    assert 'base_financial_impact_variance' in engine.parameters

def test_run_supply_chain_disruption_scenario(engine):
    """
    Test the MVP: a full supply-chain disruption scenario.
    """
    # 1. Define scenario input
    scenario = ScenarioInput(
        scenario_type="supply_chain_disruption",
        target_supplier="Test-Supplier-X",
        disruption_level=0.5,
        duration_days=30,
        simulations=100  # Use fewer simulations for a fast test
    )
    
    # 2. Run the simulation
    result = engine.run_supply_chain_disruption(scenario)
    
    # 3. Validate the result object
    assert result is not None
    assert isinstance(result, SimulationResult)
    assert result.scenario_input == scenario
    assert result.disclaimer is not None
    assert "LEGAL/ETHICAL DISCLAIMER" in result.disclaimer

    # 4. Validate the impact metrics
    metrics = result.impact_metrics
    assert isinstance(metrics, ImpactMetrics)
    
    # Check that financial metrics are calculated and plausible
    assert metrics.financial_loss_estimate_mean > 0
    assert metrics.financial_loss_estimate_std >= 0
    assert metrics.confidence_interval_loss[0] >= 0
    assert metrics.confidence_interval_loss[1] >= metrics.confidence_interval_loss[0]
    
    # Check that operational metrics are calculated
    assert metrics.operational_downtime_days_mean > 0
    assert metrics.operational_downtime_days_std >= 0

    # 5. Validate summary
    assert "initial_event" in result.scenario_tree_summary
    assert result.scenario_tree_summary["target"] == "Test-Supplier-X"

def test_scenario_type_mismatch(engine):
    """
    Test that the method raises a ValueError for the wrong scenario type.
    """
    scenario = ScenarioInput(
        scenario_type="cyberattack",  # Incorrect type for this method
        target_supplier="Test-Supplier-X",
        disruption_level=0.5,
        duration_days=30
    )
    
    with pytest.raises(ValueError, match="only supports 'supply_chain_disruption'"):
        engine.run_supply_chain_disruption(scenario)

def test_internal_monte_carlo_simulation(engine):
    """
    Test the internal Monte Carlo simulation method directly.
    """
    n_sims = 1000
    base_value = 100000
    variance = 0.1
    
    results = engine._run_monte_carlo(base_value, variance, n_sims)
    
    assert len(results) == n_sims
    # Check that all results are non-negative
    assert np.all(results >= 0)
    # Check that the mean is close to the base value
    assert base_value * 0.9 < np.mean(results) < base_value * 1.1

def test_internal_monte_carlo_zero_base(engine):
    """
    Test the Monte Carlo simulation with a base value of zero.
    """
    n_sims = 100
    results = engine._run_monte_carlo(0, 0.2, n_sims)
    assert len(results) == n_sims
    assert np.all(results == 0)