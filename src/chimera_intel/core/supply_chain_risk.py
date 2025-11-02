"""
Module for Supply Chain Risk AI.

Analyzes software dependencies and hardware providers to detect
upstream vulnerabilities and assess supply chain risk.
"""

import logging
from typing import Optional, Dict, Any, List

import typer
from .config_loader import API_KEYS
from .database import save_scan_to_db
from .http_client import sync_client
from .schemas import (
    SupplyChainRiskResult,
    SoftwareComponent,
    SupplyChainVulnerability,
)
from .utils import console, save_or_print_results

logger = logging.getLogger(__name__)

# --- Mock Vulnerability Database API ---
# In a real implementation, this would point to OSV, Snyk, NIST NVD, etc.
MOCK_VULN_DB_URL = "https://api.mock-vuln-db.com/v1/check"


def analyze_supply_chain_risk(
    components: List[SoftwareComponent],
) -> SupplyChainRiskResult:
    """
    Analyzes a list of software components for upstream vulnerabilities.
    
    Simulates checking a vulnerability database API.
    """
    api_key = API_KEYS.vuln_db_api_key  # Assumes a VULN_DB_API_KEY in config
    if not api_key:
        return SupplyChainRiskResult(
            target_components=components,
            error="Vulnerability Database API key (VULN_DB_API_KEY) is not configured.",
        )

    logger.info(f"Analyzing {len(components)} components for supply chain risk...")
    
    headers = {"X-API-KEY": api_key}
    # In a real API, you'd likely batch-post the components.
    # Here, we'll simulate checking them one by one.
    
    found_vulnerabilities: List[SupplyChainVulnerability] = []
    total_risk_score = 0.0

    try:
        for component in components:
            params = {"name": component.name, "version": component.version}
            
            # Simulate a request to the vulnerability database
            response = sync_client.get(MOCK_VULN_DB_URL, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            if data.get("vulnerabilities"):
                for vuln in data["vulnerabilities"]:
                    sev = vuln.get("severity", "UNKNOWN").upper()
                    
                    if sev == "CRITICAL":
                        total_risk_score += 10
                    elif sev == "HIGH":
                        total_risk_score += 7
                    elif sev == "MEDIUM":
                        total_risk_score += 4

                    found_vulnerabilities.append(
                        SupplyChainVulnerability(
                            cve_id=vuln.get("cve_id", "N/A"),
                            severity=sev,
                            description=vuln.get("description", "No description."),
                            component_name=component.name,
                            component_version=component.version,
                        )
                    )

        # Calculate final risk score (simple average, max 10.0)
        final_score = 0.0
        if components:
            final_score = min(10.0, total_risk_score / len(components))

        summary = (
            f"Found {len(found_vulnerabilities)} vulnerabilities across "
            f"{len(components)} components. "
            f"Average risk score: {final_score:.1f}/10.0"
        )
        
        return SupplyChainRiskResult(
            target_components=components,
            found_vulnerabilities=found_vulnerabilities,
            risk_score=final_score,
            summary=summary,
        )

    except Exception as e:
        logger.error(f"An error occurred while querying vuln database: {e}")
        return SupplyChainRiskResult(
            target_components=components, error=f"An API error occurred: {e}"
        )


# --- Typer CLI Application ---

supply_chain_app = typer.Typer()

@supply_chain_app.command("analyze")
def run_supply_chain_analysis(
    components: List[str] = typer.Argument(
        ...,
        help="List of components to analyze (e.g., 'requests:2.28.1' 'numpy:1.23.5').",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes a list of software components (e.g., from a requirements.txt)
    for known upstream vulnerabilities.
    """
    parsed_components: List[SoftwareComponent] = []
    for item in components:
        try:
            name, version = item.split(":")
            parsed_components.append(SoftwareComponent(name=name, version=version))
        except ValueError:
            console.print(f"[bold red]Invalid component format:[/bold red] '{item}'. Skipping. "
                          "Please use 'name:version' format.")
            
    if not parsed_components:
        console.print("[bold red]No valid components to analyze.[/bold red]")
        raise typer.Exit(code=1)

    with console.status("[bold cyan]Analyzing supply chain risk...[/bold cyan]"):
        results_model = analyze_supply_chain_risk(parsed_components)
    
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    
    # Save to DB
    target_names = ", ".join([c.name for c in parsed_components])
    save_scan_to_db(
        target=target_names, module="supply_chain_risk", data=results_dict
    )