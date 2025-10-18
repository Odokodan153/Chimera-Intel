"""
Module for Adversary Emulation & TTP Mapping.

Maps known vulnerabilities (CVEs) to the MITRE ATT&CK framework to understand
how they might be exploited by real-world adversaries.
"""

import typer
import logging
from typing import List, Optional
from mitreattack.stix20 import MitreAttackData  # type: ignore
from .schemas import TTPMappingResult, MappedTechnique
from .utils import save_or_print_results
from .database import save_scan_to_db

logger = logging.getLogger(__name__)


def map_cves_to_ttp(cve_ids: List[str]) -> TTPMappingResult:
    """
    Maps a list of CVE IDs to their corresponding MITRE ATT&CK techniques.

    Args:
        cve_ids (List[str]): A list of CVE identifiers to map.

    Returns:
        TTPMappingResult: A Pydantic model with the mapping results.
    """
    logger.info(f"Mapping {len(cve_ids)} CVEs to MITRE ATT&CK techniques.")
    mapped_techniques: List[MappedTechnique] = []

    try:
        # Load the MITRE ATT&CK data (downloads it on first run)

        attack = MitreAttackData("enterprise-attack.json")

        for cve_id in cve_ids:
            # Find techniques related to a specific CVE

            techniques = attack.get_techniques_by_cve_id(cve_id)

            for tech in techniques:
                # A technique can belong to multiple tactics (e.g., Discovery, Execution)

                tactics = "N/A"
                if tech.get("kill_chain_phases"):
                    tactics = ", ".join(
                        [
                            phase.get("phase_name", "unknown")
                            for phase in tech.get("kill_chain_phases", [])
                        ]
                    )
                technique_id = "N/A"
                if tech.get("external_references"):
                    technique_id = tech["external_references"][0].get(
                        "external_id", "N/A"
                    )
                mapped_techniques.append(
                    MappedTechnique(
                        cve_id=cve_id,
                        technique_id=technique_id,
                        technique_name=tech.get("name", "Unknown"),
                        tactic=tactics,
                    )
                )
        return TTPMappingResult(
            total_cves_analyzed=len(cve_ids), mapped_techniques=mapped_techniques
        )
    except Exception as e:
        logger.error(f"Failed to map CVEs to ATT&CK: {e}")
        return TTPMappingResult(
            total_cves_analyzed=len(cve_ids), error=f"An error occurred: {e}"
        )


# --- Typer CLI Application ---


ttp_app = typer.Typer()


# --- FIX: Renamed function to 'map_cve' and removed explicit name from decorator ---


@ttp_app.command()
def map_cve(
    cve_ids: List[str] = typer.Argument(
        ..., help="One or more CVE IDs to map (e.g., CVE-2021-44228)."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Maps CVE vulnerabilities to MITRE ATT&CK techniques."""
    results_model = map_cves_to_ttp(cve_ids)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=", ".join(cve_ids), module="ttp_mapper_cve", data=results_dict
    )
