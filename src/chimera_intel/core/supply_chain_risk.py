"""
Module for Supply Chain Risk AI.

Analyzes software dependencies and hardware providers to detect
upstream vulnerabilities and assess supply chain risk.

This version queries the public OSV.dev API.
"""

import logging
from typing import Optional, List, Dict, Any
import typer
# config_loader is no longer needed for API_KEYS
# from .config_loader import API_KEYS
from .database import save_scan_to_db
from .http_client import sync_client
from .schemas import (
    SupplyChainRiskResult,
    SoftwareComponent,
    SupplyChainVulnerability,
)
from .utils import console, save_or_print_results

logger = logging.getLogger(__name__)

# --- Real Vulnerability Database API ---
# This is the real batch query endpoint for OSV.dev
OSV_BATCH_QUERY_URL = "https://api.osv.dev/v1/querybatch"


def _get_severity_from_osv(vuln: Dict[str, Any]) -> str:
    """
    Parses the OSV vulnerability record to find the highest CVSS score
    and map it to a qualitative severity rating.
    """
    highest_score = 0.0
    
    # OSV severity is an array of scoring systems (e.g., CVSS_V3)
    for severity_entry in vuln.get("severity", []):
        if severity_entry.get("type") == "CVSS_V3":
            try:
                # The 'score' can be a vector string or a number.
                # We look for a simple numerical score.
                # In a more robust parser, you'd parse the vector.
                score = float(severity_entry.get("score"))
                if score > highest_score:
                    highest_score = score
            except (ValueError, TypeError):
                # Could be a vector string like "CVSS:3.1/AV:N/AC:L/..."
                # For this example, we'll ignore it if it's not a simple number.
                pass

    # If we found a CVSS score, map it.
    if highest_score > 0.0:
        if highest_score >= 9.0:
            return "CRITICAL"
        if highest_score >= 7.0:
            return "HIGH"
        if highest_score >= 4.0:
            return "MEDIUM"
        if highest_score >= 0.1:
            return "LOW"
            
    # Fallback if no CVSS_V3 score was found
    return "UNKNOWN"


def analyze_supply_chain_risk(
    components: List[SoftwareComponent],
) -> SupplyChainRiskResult:
    """
    Analyzes a list of software components for upstream vulnerabilities
    by querying the public OSV.dev API.
    """
    logger.info(f"Analyzing {len(components)} components for supply chain risk via OSV.dev...")

    # Build the batch query for OSV.dev
    # We assume 'PyPI' ecosystem as this is a Python project.
    # This could be made more flexible if needed.
    queries = []
    for component in components:
        queries.append({
            "package": {"name": component.name, "ecosystem": "PyPI"},
            "version": component.version,
        })
    
    batch_request_body = {"queries": queries}
    
    found_vulnerabilities: List[SupplyChainVulnerability] = []
    total_risk_score = 0.0

    try:
        # Send a single POST request with all component queries
        response = sync_client.post(OSV_BATCH_QUERY_URL, json=batch_request_body)
        response.raise_for_status()
        data = response.json()

        # The response contains a 'results' list in the same order as our queries
        results = data.get("results", [])
        
        for i, component_result in enumerate(results):
            component = components[i] # Get the component we queried for
            
            # 'vulns' is the list of vulnerabilities for that component
            if component_result and component_result.get("vulns"):
                for vuln in component_result["vulns"]:
                    sev = _get_severity_from_osv(vuln)
                    
                    if sev == "CRITICAL":
                        total_risk_score += 10
                    elif sev == "HIGH":
                        total_risk_score += 7
                    elif sev == "MEDIUM":
                        total_risk_score += 4
                    elif sev == "LOW":
                        total_risk_score += 1

                    found_vulnerabilities.append(
                        SupplyChainVulnerability(
                            cve_id=vuln.get("id", "N/A"),
                            severity=sev,
                            description=vuln.get("summary", vuln.get("details", "No description.")),
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
        logger.error(f"An error occurred while querying OSV.dev API: {e}")
        return SupplyChainRiskResult(
            target_components=components, error=f"An API error occurred: {e}"
        )


# --- Typer CLI Application ---
# (This part is identical to your original file)

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
            # Assume PyPI ecosystem if not specified
            if ":" in item:
                name, version = item.split(":")
            else:
                console.print(f"[bold red]Invalid component format:[/bold red] '{item}'. Skipping. "
                          "Please use 'name:version' format.")
                continue
                
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