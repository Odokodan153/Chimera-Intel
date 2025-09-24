"""
Core Correlation Engine for Chimera Intel.

This module acts as the central brain for automated analysis, triggering follow-up
scans based on the results of a completed scan.
"""

import subprocess
import logging
from typing import Dict, Any
from .utils import console
from .differ import get_last_two_scans

logger = logging.getLogger(__name__)


def run_correlations(target: str, module: str, scan_data: Dict[str, Any]):
    """
    Analyzes scan data and triggers new scans based on a set of rules.

    Args:
        target (str): The primary target of the scan that just finished.
        module (str): The name of the module that produced the data.
        scan_data (Dict[str, Any]): The JSON data from the completed scan.
    """
    logger.info(f"Running correlation engine for '{target}' from module '{module}'.")

    # --- Rule 1: New IP Address Found ---

    if module == "footprint":
        _, previous_scan = get_last_two_scans(target, "footprint")
        if previous_scan:
            current_ips = set(
                scan_data.get("footprint", {}).get("dns_records", {}).get("A", [])
            )
            previous_ips = set(
                previous_scan.get("footprint", {}).get("dns_records", {}).get("A", [])
            )
            new_ips = current_ips - previous_ips
            for ip in new_ips:
                logger.info(
                    f"Correlation: New IP {ip} found for {target}. Triggering vulnerability scan."
                )
                _trigger_scan(
                    ["defensive", "vuln", "run", ip],
                    f"New IP {ip} found for {target}",
                )
    # --- Rule 2: New Subdomain Found ---

    if module == "footprint":
        _, previous_scan = get_last_two_scans(target, "footprint")
        if previous_scan:
            current_subdomains = {
                res.get("domain")
                for res in scan_data.get("footprint", {})
                .get("subdomains", {})
                .get("results", [])
            }
            previous_subdomains = {
                res.get("domain")
                for res in previous_scan.get("footprint", {})
                .get("subdomains", {})
                .get("results", [])
            }
            new_subdomains = current_subdomains - previous_subdomains
            for sub in new_subdomains:
                if sub:
                    logger.info(
                        f"Correlation: New subdomain {sub} found for {target}. Triggering web analysis."
                    )
                    _trigger_scan(
                        ["scan", "web", "run", sub],
                        f"New subdomain {sub} found",
                    )
    # --- Rule 3: Critical CVE Found ---

    if module == "vulnerability_scanner":
        for host in scan_data.get("scanned_hosts", []):
            for port in host.get("open_ports", []):
                for cve in port.get("vulnerabilities", []):
                    if cve.get("cvss_score", 0.0) >= 9.0:
                        cve_id = cve.get("id")
                        logger.info(
                            f"Correlation: Critical CVE {cve_id} found on {host.get('host')}. Triggering TTP mapping."
                        )
                        _trigger_scan(
                            ["ttp", "map-cve", cve_id],
                            f"Critical CVE {cve_id} found",
                        )


def _trigger_scan(command: list, reason: str):
    """
    Helper function to launch a new Chimera Intel scan as a subprocess.

    Args:
        command (list): The list of arguments for the chimera command.
        reason (str): The reason the scan is being triggered, for logging.
    """
    try:
        full_command = ["chimera"] + command
        console.print(
            f"\n[bold yellow]🧠 Correlation Engine Triggered[/bold yellow]: [cyan]{reason}[/cyan]"
        )
        console.print(f"  [dim]-> Running command: {' '.join(full_command)}[/dim]")
        # We run this in the background and don't wait for it to complete.
        # This prevents the initial scan from hanging.

        subprocess.Popen(
            full_command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        logger.error(f"Failed to trigger correlated scan '{' '.join(command)}': {e}")
