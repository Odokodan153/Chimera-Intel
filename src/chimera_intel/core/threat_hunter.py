"""
Module for proactive threat hunting.

This module leverages threat actor intelligence to proactively hunt for known
indicators of compromise (IOCs) within local log files.
"""

import typer
import logging
import os
from typing import Optional, List
from .schemas import ThreatHuntResult, DetectedIOC
from .utils import save_or_print_results
from .database import save_scan_to_db
from .threat_actor_intel import get_threat_actor_profile

logger = logging.getLogger(__name__)


def hunt_for_iocs_in_log(log_file: str, actor_name: str) -> ThreatHuntResult:
    """
    Hunts for a threat actor's IOCs within a given log file.

    Args:
        log_file (str): The path to the log file to be scanned.
        actor_name (str): The name of the threat actor to source IOCs from.

    Returns:
        ThreatHuntResult: A Pydantic model with the results of the threat hunt.
    """
    logger.info(
        f"Starting threat hunt in '{log_file}' for IOCs related to '{actor_name}'."
    )

    if not os.path.exists(log_file):
        error_msg = f"Log file not found at path: {log_file}"
        logger.error(error_msg)
        return ThreatHuntResult(
            log_file=log_file,
            threat_actor=actor_name,
            total_iocs_found=0,
            error=error_msg,
        )
    # 1. Get Threat Actor Profile

    actor_profile = get_threat_actor_profile(actor_name)
    if actor_profile.error or not actor_profile.actor:
        error_msg = f"Could not retrieve profile for threat actor '{actor_name}'. Error: {actor_profile.error}"
        logger.error(error_msg)
        return ThreatHuntResult(
            log_file=log_file,
            threat_actor=actor_name,
            total_iocs_found=0,
            error=error_msg,
        )
    iocs_to_hunt = set(actor_profile.actor.known_indicators)
    if not iocs_to_hunt:
        return ThreatHuntResult(
            log_file=log_file,
            threat_actor=actor_name,
            total_iocs_found=0,
            message="No IOCs found in the actor's profile to hunt for.",
        )
    logger.info(f"Hunting for {len(iocs_to_hunt)} unique IOCs from '{actor_name}'.")

    # 2. Scan the log file for IOCs

    detected_iocs: List[DetectedIOC] = []
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for ioc in iocs_to_hunt:
                    if ioc in line:
                        detected_iocs.append(
                            DetectedIOC(
                                ioc=ioc,
                                line_number=line_num,
                                log_line=line.strip(),
                            )
                        )
    except Exception as e:
        error_msg = f"Failed to read or process log file: {e}"
        logger.error(error_msg)
        return ThreatHuntResult(
            log_file=log_file,
            threat_actor=actor_name,
            total_iocs_found=0,
            error=error_msg,
        )
    return ThreatHuntResult(
        log_file=log_file,
        threat_actor=actor_name,
        total_iocs_found=len(detected_iocs),
        detected_iocs=detected_iocs,
    )


# --- Typer CLI Application ---


threat_hunter_app = typer.Typer()


@threat_hunter_app.command("run")
def run_threat_hunt(
    log_file: str = typer.Option(
        ..., "--log-file", help="Path to the log file to scan."
    ),
    actor_name: str = typer.Option(
        ..., "--actor", help="The threat actor to hunt for (e.g., 'APT28')."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Hunts for a threat actor's known IOCs in a local log file.
    """
    results_model = hunt_for_iocs_in_log(log_file, actor_name)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=f"{actor_name}_in_{os.path.basename(log_file)}",
        module="cybint_threat_hunt",
        data=results_dict,
    )
