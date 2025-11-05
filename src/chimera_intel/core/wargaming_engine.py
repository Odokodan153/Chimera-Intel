import numpy as np
import logging
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Literal, Tuple

# --- CLI Imports ---
# These are new in this file
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing_extensions import Annotated
# ---------------------

# Configure logger
logger = logging.getLogger(__name__)

#
# --- Pydantic Models (Unchanged) ---
#
class ScenarioInput(BaseModel):
    """
    Defines the input parameters for a wargaming scenario.
    """
    scenario_type: str = Field(..., description="Type of scenario to run (e.g., 'supply_chain_disruption').")
    target_supplier: str = Field(..., description="The name of the supplier being targeted or affected.")
    disruption_level: float = Field(
        default=0.5, 
        description="Severity of the disruption (0.0 to 1.0).",
        ge=0.0,
        le=1.0
    )
    duration_days: int = Field(default=30, description="Estimated duration of the disruption in days.", gt=0)
    simulations: int = Field(default=1000, description="Number of Monte Carlo simulations to run.", gt=0)
    distribution_type: Literal["normal", "lognormal", "triangular"] = Field(
        default="normal", 
        description="The probability distribution to use for simulations."
    )

class ImpactMetrics(BaseModel):
    """
    Quantified impacts calculated from the simulation.
    """
    financial_loss_estimate_mean: float
    financial_loss_estimate_std: float
    financial_loss_estimate_min: float
    financial_loss_estimate_max: float
    operational_downtime_days_mean: float
    operational_downtime_days_std: float
    operational_downtime_days_min: float
    operational_downtime_days_max: float
    confidence_interval_loss: Tuple[float, float]
    
class SimulationResult(BaseModel):
    """
    Contains the results of a completed scenario simulation.
    """
    scenario_input: ScenarioInput
    impact_metrics: ImpactMetrics
    scenario_tree_summary: Dict[str, Any] = Field(default_factory=dict)
    disclaimer: str = Field(
        default="LEGAL/ETHICAL DISCLAIMER: This output is based on a simulation and does not represent a deterministic prediction of future events. It is intended for analytical and planning purposes only."
    )

#
# --- Core Engine Class (Unchanged) ---
#
class WargamingEngine:
    """
    A multi-domain simulator for running 'what-if' scenarios.
    
    This engine uses plug-in models and data sources to quantify the impact
    of events like sanctions, supply-chain breaks, and cyberattacks.
    """

    def __init__(self, historical_data: List[Dict[str, Any]] = None):
        """
        Initializes the engine.
        
        Args:
            historical_data: A list of dictionaries representing historical events,
                             used to tune simulation parameters.
                             Example: [{"type": "supply", "duration": 10, "severity": 0.3, "actual_loss": 500000}]
        """
        self.domain_models = self._load_plug_in_models()
        self.parameters = self._tune_parameters(historical_data or [])
        logger.info(f"WargamingEngine initialized with parameters: {self.parameters}")

    def _load_plug_in_models(self) -> Dict[str, Any]:
        """
        Placeholder for loading plug-in domain models.
        In a real implementation, this would dynamically load models.
        """
        models = {
            'supply_chain_model': {
                'cost_per_day_multiplier': 150000,
                'downtime_factor': 1.2
            }
        }
        logger.debug(f"Loaded {len(models)} domain models.")
        return models

    def _tune_parameters(self, historical_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Tunes model parameters based on historical data.
        """
        default_params = {
            'base_financial_impact_variance': 0.3,
            'base_downtime_variance': 0.2
        }
        
        if not historical_data:
            logger.info("No historical data provided. Using default simulation parameters.")
            return default_params
            
        logger.info(f"Tuning parameters based on {len(historical_data)} historical events.")
        
        financial_variances = []
        model = self.domain_models.get('supply_chain_model', {})
        
        for event in historical_data:
            if event.get("type") == "supply_chain_disruption" and "severity" in event and "duration" in event and "actual_loss" in event:
                try:
                    base_daily_loss = model.get('cost_per_day_multiplier', 150000) * event["severity"]
                    expected_loss = base_daily_loss * event["duration"]
                    
                    if expected_loss > 0:
                        variance = (event["actual_loss"] - expected_loss) / expected_loss
                        financial_variances.append(variance)
                    
                except Exception as e:
                    logger.warning(f"Could not parse historical event {event}: {e}")

        if financial_variances:
            tuned_financial_variance = float(np.std(financial_variances))
            if 0 < tuned_financial_variance < 1.0:
                 default_params['base_financial_impact_variance'] = tuned_financial_variance
                 logger.info(f"Tuned financial impact variance to: {tuned_financial_variance:.4f}")

        return default_params

    def _run_monte_carlo(
        self, 
        base_value: float, 
        variance: float, 
        n_sims: int, 
        distribution_type: str
    ) -> np.ndarray:
        """
        Runs a simple Monte Carlo simulation using a specified distribution.
        """
        logger.debug(
            f"Running MC sim: base_value={base_value}, variance={variance}, "
            f"n_sims={n_sims}, distribution={distribution_type}"
        )
        
        if base_value == 0:
            return np.zeros(n_sims)
        
        variance = max(0.01, variance) 

        if distribution_type == "normal":
            std_dev = base_value * variance
            simulated_values = np.random.normal(loc=base_value, scale=std_dev, size=n_sims)
        
        elif distribution_type == "lognormal":
            mu = np.log(base_value) 
            sigma = variance 
            simulated_values = np.random.lognormal(mean=mu, sigma=sigma, size=n_sims)

        elif distribution_type == "triangular":
            v_min = base_value * (1 - (variance * 1.5))
            v_mode = base_value
            v_max = base_value * (1 + (variance * 1.5))
            simulated_values = np.random.triangular(left=v_min, mode=v_mode, right=v_max, size=n_sims)
            
        else:
            logger.warning(f"Unknown distribution '{distribution_type}'. Defaulting to 'normal'.")
            std_dev = base_value * variance
            simulated_values = np.random.normal(loc=base_value, scale=std_dev, size=n_sims)

        logger.debug(f"First 5 MC samples: {simulated_values[:5]}")
        
        return np.maximum(0, simulated_values)

    def run_supply_chain_disruption(self, scenario_input: ScenarioInput) -> SimulationResult:
        """
        Runs the MVP scenario: supply-chain disruption for a target supplier.
        """
        if scenario_input.scenario_type != 'supply_chain_disruption':
            raise ValueError("This method only supports 'supply_chain_disruption' scenarios.")

        logger.info(f"Running '{scenario_input.distribution_type}' supply-chain disruption for '{scenario_input.target_supplier}'...")
        
        model = self.domain_models.get('supply_chain_model')
        if not model:
            logger.error("Supply chain domain model not loaded.")
            raise ImportError("Failed to load 'supply_chain_model'.")

        base_daily_loss = model['cost_per_day_multiplier'] * scenario_input.disruption_level
        base_total_loss = base_daily_loss * scenario_input.duration_days
        base_downtime = (scenario_input.duration_days * scenario_input.disruption_level) * model['downtime_factor']
        
        n_sims = scenario_input.simulations
        dist_type = scenario_input.distribution_type
        
        simulated_losses = self._run_monte_carlo(
            base_total_loss, 
            self.parameters['base_financial_impact_variance'], 
            n_sims,
            dist_type
        )
        
        simulated_downtimes = self._run_monte_carlo(
            base_downtime,
            self.parameters['base_downtime_variance'],
            n_sims,
            dist_type
        )

        metrics = ImpactMetrics(
            financial_loss_estimate_mean=float(np.mean(simulated_losses)),
            financial_loss_estimate_std=float(np.std(simulated_losses)),
            financial_loss_estimate_min=float(np.min(simulated_losses)),
            financial_loss_estimate_max=float(np.max(simulated_losses)),
            confidence_interval_loss=(
                float(np.percentile(simulated_losses, 2.5)), 
                float(np.percentile(simulated_losses, 97.5))
            ),
            operational_downtime_days_mean=float(np.mean(simulated_downtimes)),
            operational_downtime_days_std=float(np.std(simulated_downtimes)),
            operational_downtime_days_min=float(np.min(simulated_downtimes)),
            operational_downtime_days_max=float(np.max(simulated_downtimes)),
        )

        summary = {
            "initial_event": "Supply Chain Disruption",
            "target": scenario_input.target_supplier,
            "distribution": scenario_input.distribution_type,
            "simulations": scenario_input.simulations,
            "financial_loss": {
                "mean": metrics.financial_loss_estimate_mean,
                "std_dev": metrics.financial_loss_estimate_std,
                "min": metrics.financial_loss_estimate_min,
                "max": metrics.financial_loss_estimate_max,
                "confidence_interval_95": metrics.confidence_interval_loss,
            },
            "operational_downtime": {
                "mean": metrics.operational_downtime_days_mean,
                "std_dev": metrics.operational_downtime_days_std,
                "min": metrics.operational_downtime_days_min,
                "max": metrics.operational_downtime_days_max,
            }
        }
        
        result = SimulationResult(
            scenario_input=scenario_input,
            impact_metrics=metrics,
            scenario_tree_summary=summary
        )
        
        logger.info(f"Scenario complete for '{scenario_input.target_supplier}'. Mean estimated loss: ${metrics.financial_loss_estimate_mean:,.2f}")
        
        return result

#
# --- CLI Plugin Definition ---
#
# This Typer app is imported by the plugin's main.py
#
plugin = typer.Typer(
    help="🎲 Massive Scenario & Wargaming Engine: Run 'what-if' scenarios to see quantified impacts."
)
console = Console()

@plugin.command(
    "run-supply-chain",
    help="Run a supply-chain disruption scenario (MVP)."
)
def run_scenario(
    target_supplier: Annotated[str, typer.Option(
        help="The name of the supplier to simulate a disruption for."
    )] = "Supplier-Alpha",
    
    disruption_level: Annotated[float, typer.Option(
        min=0.0, max=1.0, 
        help="Severity of the disruption (0.0 = no impact, 1.0 = total failure)."
    )] = 0.5,
    
    duration_days: Annotated[int, typer.Option(
        min=1, 
        help="Estimated duration of the disruption in days."
    )] = 30,
    
    simulations: Annotated[int, typer.Option(
        min=100, 
        help="Number of Monte Carlo simulations to run."
    )] = 2000,

    distribution_type: Annotated[Literal["normal", "lognormal", "triangular"], typer.Option(
        help="The probability distribution to use for simulations."
    )] = "normal"
):
    """
    Runs the MVP supply-chain disruption scenario and prints a formatted report.
    """
    console.print(
        f"[bold blue]Running Wargaming Scenario...[/]\n"
        f"  [cyan]Type:[/] Supply-Chain Disruption\n"
        f"  [cyan]Target:[/] {target_supplier}\n"
        f"  [cyan]Severity:[/] {disruption_level*100}%\n"
        f"  [cyan]Duration:[/] {duration_days} days\n"
        f"  [cyan]Distribution:[/] {distribution_type}\n"
        f"  [cyan]Simulations:[/] {simulations:n}"
    )

    try:
        # 1. Initialize engine and input
        # Note: We don't pass historical data from the CLI for now.
        engine = WargamingEngine() 
        scenario = ScenarioInput(
            scenario_type="supply_chain_disruption",
            target_supplier=target_supplier,
            disruption_level=disruption_level,
            duration_days=duration_days,
            simulations=simulations,
            distribution_type=distribution_type
        )
        
        # 2. Run simulation
        with console.status("[spinner] Running Monte Carlo simulations..."):
            results = engine.run_supply_chain_disruption(scenario)
        
        console.line(2)
        console.print(Panel(
            f"[bold green]Simulation Complete for '{results.scenario_input.target_supplier}'[/]",
            expand=False,
            border_style="green"
        ))
        
        # 3. Create results table
        table = Table(title="Quantified Impact Metrics", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="dim")
        table.add_column("Value", style="bold")
        
        metrics = results.impact_metrics
        table.add_row("Est. Financial Loss (Mean)", f"${metrics.financial_loss_estimate_mean:,.2f}")
        table.add_row("Est. Financial Loss (StdDev)", f"${metrics.financial_loss_estimate_std:,.2f}")
        table.add_row("Est. Financial Loss (Min)", f"${metrics.financial_loss_estimate_min:,.2f}")
        table.add_row("Est. Financial Loss (Max)", f"${metrics.financial_loss_estimate_max:,.2f}")
        table.add_row(
            "95% Confidence Interval (Loss)", 
            f"(${metrics.confidence_interval_loss[0]:,.2f} - ${metrics.confidence_interval_loss[1]:,.2f})"
        )
        table.add_row("Est. Operational Downtime (Mean)", f"{metrics.operational_downtime_days_mean:.1f} days")
        table.add_row("Est. Operational Downtime (Min/Max)", f"{metrics.operational_downtime_days_min:.1f} / {metrics.operational_downtime_days_max:.1f} days")
        
        console.print(table)
        console.line()
        
        # 4. Print disclaimer
        console.print(Panel(
            f"[dim italic]{results.disclaimer}[/]",
            title="Disclaimer",
            border_style="yellow",
            expand=False
        ))

    except Exception as e:
        console.print(f"[bold red]Error running scenario:[/_] {e}")
        raise typer.Exit(code=1)

#
# --- Internal Test Runner (Unchanged) ---
#
if __name__ == "__main__":
    # Set logging to DEBUG to see new log messages
    logging.basicConfig(level=logging.INFO)
    logger.setLevel(logging.DEBUG)
    
    # Example historical data for tuning
    hist_data = [
        {"type": "supply_chain_disruption", "duration": 20, "severity": 0.5, "actual_loss": 1800000},
        {"type": "supply_chain_disruption", "duration": 10, "severity": 0.8, "actual_loss": 1100000},
        {"type": "supply_chain_disruption", "duration": 40, "severity": 0.2, "actual_loss": 1300000},
    ]
    
    engine = WargamingEngine(historical_data=hist_data)
    
    scenario_norm = ScenarioInput(
        scenario_type="supply_chain_disruption",
        target_supplier="Supplier-Alpha (Normal)",
        disruption_level=0.75,
        duration_days=60,
        simulations=5000,
        distribution_type="normal"
    )
    
    scenario_log = ScenarioInput(
        scenario_type="supply_chain_disruption",
        target_supplier="Supplier-Beta (Lognormal)",
        disruption_level=0.75,
        duration_days=60,
        simulations=5000,
        distribution_type="lognormal"
    )

    for scenario in [scenario_norm, scenario_log]:
        try:
            results = engine.run_supply_chain_disruption(scenario)
            
            print(f"\n--- Wargaming Simulation Result (Dist: {results.scenario_input.distribution_type}) ---")
            print(f"Target Supplier: {results.scenario_input.target_supplier}")
            print("\n--- Quantified Impact Metrics ---")
            print(f"  Est. Financial Loss (Mean): ${results.impact_metrics.financial_loss_estimate_mean:,.2f}")
            print(f"  Est. Financial Loss (Min/Max): ${results.impact_metrics.financial_loss_estimate_min:,.2f} / ${results.impact_metrics.financial_loss_estimate_max:,.2f}")
            print(f"  95% Confidence Interval: (${results.impact_metrics.confidence_interval_loss[0]:,.2f} - ${results.impact_metrics.confidence_interval_loss[1]:,.2f})")
            print(f"  Est. Op. Downtime (Mean): {results.impact_metrics.operational_downtime_days_mean:.1f} days")
            print(f"\n{results.disclaimer}")

        except Exception as e:
            logger.error(f"Failed to run scenario: {e}", exc_info=True)