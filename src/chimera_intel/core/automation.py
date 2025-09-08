"""
Module for high-level analysis, automation, and integration.

This module provides tools for data enrichment, threat modeling,
behavioral analysis (UEBA), and workflow automation.
"""

import yaml
import typer
import logging
import asyncio
import subprocess
import os
import csv
from collections import defaultdict
from typing import List, Optional, Set, DefaultDict
from .schemas import (
    CVEEnrichmentResult,
    EnrichedCVE,
    VTSubmissionResult,
    EnrichmentResult,
    EnrichedIOC,
    ThreatModelResult,
    AttackPath,
    UEBAResult,
    BehavioralAnomaly,
)
from .utils import save_or_print_results, console
from .config_loader import API_KEYS
from .http_client import sync_client
from .threat_intel import get_threat_intel_otx
from .database import get_aggregated_data_for_target

UserIPs = DefaultDict[str, Set[str]]
UserHours = DefaultDict[str, Set[int]]


logger = logging.getLogger(__name__)


# --- Data Enrichment ---


async def enrich_iocs(iocs: List[str]) -> EnrichmentResult:
    """Enriches Indicators of Compromise (IOCs) with threat intelligence from OTX.

    This function takes a list of IOCs (IP addresses, domains, etc.) and queries
    the AlienVault OTX API to determine if they are associated with known malicious
    activity.

    Args:
        iocs (List[str]): A list of indicators to enrich.

    Returns:
        EnrichmentResult: A Pydantic model containing the enriched IOC data or an error.
    """
    logger.info(f"Enriching {len(iocs)} IOCs.")

    if not API_KEYS.otx_api_key:
        return EnrichmentResult(
            total_enriched=0, error="OTX API key not found in .env file."
        )
    tasks = [get_threat_intel_otx(ioc) for ioc in iocs]
    results = await asyncio.gather(*tasks)

    enriched_iocs = []
    for res in results:
        if res and not res.error:
            enriched_iocs.append(
                EnrichedIOC(
                    indicator=res.indicator,
                    is_malicious=res.is_malicious,
                    source="AlienVault OTX",
                    details=f"Found in {res.pulse_count} threat pulse(s).",
                )
            )
    return EnrichmentResult(
        total_enriched=len(enriched_iocs), enriched_iocs=enriched_iocs
    )


def enrich_cves(cve_ids: List[str]) -> CVEEnrichmentResult:
    """Enriches a list of CVE IDs with details from the Vulners API.

    Args:
        cve_ids (List[str]): A list of CVE identifiers (e.g., "CVE-2021-44228").

    Returns:
        CVEEnrichmentResult: A Pydantic model containing detailed information for
                             each found CVE or an error.
    """
    api_key = API_KEYS.vulners_api_key
    if not api_key:
        return CVEEnrichmentResult(
            total_enriched=0, error="Vulners API key not found in .env file."
        )
    logger.info(f"Enriching {len(cve_ids)} CVEs from Vulners.")
    enriched_cves: List[EnrichedCVE] = []

    try:
        url = "https://vulners.com/api/v3/search/id/"
        payload = {"apiKey": api_key, "id": cve_ids}
        response = sync_client.post(url, json=payload)
        response.raise_for_status()
        data = response.json()

        documents = data.get("data", {}).get("documents", {})
        for cve_id, doc in documents.items():
            enriched_cves.append(
                EnrichedCVE(
                    cve_id=doc.get("id", cve_id),
                    cvss_score=doc.get("cvss", {}).get("score", 0.0),
                    summary=doc.get("description", "No summary available."),
                    references=[
                        ref.get("href")
                        for ref in doc.get("references", [])
                        if ref.get("href")
                    ],
                )
            )
    except Exception as e:
        logger.error(f"Failed to enrich CVEs from Vulners: {e}")
        return CVEEnrichmentResult(
            total_enriched=0, error=f"An error occurred with the Vulners API: {e}"
        )
    return CVEEnrichmentResult(
        total_enriched=len(enriched_cves), enriched_cves=enriched_cves
    )


# --- Threat Modeling & UEBA ---


def generate_threat_model(domain: str) -> ThreatModelResult:
    """Analyzes aggregated scan data to generate potential attack paths.

    This function fetches historical scan data for a target and applies a set
    of rules to identify potential weaknesses that could be chained together
    in an attack.

    Args:
        domain (str): The target domain to model threats for.

    Returns:
        ThreatModelResult: A Pydantic model containing potential attack paths.
    """
    logger.info(f"Generating rule-based threat model for {domain}")
    aggregated_data = get_aggregated_data_for_target(domain)
    if not aggregated_data or not aggregated_data.get("modules"):
        return ThreatModelResult(
            target_domain=domain,
            error="No historical data found to build a threat model.",
        )
    potential_paths: List[AttackPath] = []
    modules = aggregated_data.get("modules", {})

    # Rule 1: Vulnerable public services

    vuln_scan = modules.get("vulnerability_scanner", {}).get("scanned_hosts", [])
    for host in vuln_scan:
        for port in host.get("open_ports", []):
            if port.get("vulnerabilities"):
                cve = port["vulnerabilities"][0]
                if cve.get("cvss_score", 0.0) >= 7.0:
                    potential_paths.append(
                        AttackPath(
                            entry_point=f"Public Host: {host.get('host')}",
                            path=[
                                f"Exploit {cve.get('id')} (CVSS: {cve.get('cvss_score')}) on service {port.get('product', 'N/A')} on port {port.get('port')}.",
                                "Gain initial access to the server.",
                                "Perform reconnaissance on the internal network.",
                            ],
                            target="Internal Network Access",
                            confidence="High",
                        )
                    )
    # Rule 2: Publicly exposed cloud storage

    cloud_scan = modules.get("cloud_osint_s3", {}).get("found_buckets", [])
    for bucket in cloud_scan:
        if bucket.get("is_public"):
            potential_paths.append(
                AttackPath(
                    entry_point="Public Internet",
                    path=[
                        f"Discover publicly accessible S3 bucket: {bucket.get('name')}.",
                        "Access and exfiltrate sensitive data stored in the bucket.",
                    ],
                    target="Sensitive Data Exfiltration",
                    confidence="High",
                )
            )
    # Rule 3: Leaked credentials

    leaks = modules.get("recon_credentials", {}).get("compromised_credentials", [])
    if leaks:
        leak = leaks[0]
        potential_paths.append(
            AttackPath(
                entry_point="Dark Web / Credential Dumps",
                path=[
                    f"Obtain leaked credential for user '{leak.get('email')}' from breach '{leak.get('source_breach')}'.",
                    "Attempt credential stuffing or password reuse attacks on corporate login portals.",
                ],
                target="User Account Compromise",
                confidence="Medium",
            )
        )
    return ThreatModelResult(target_domain=domain, potential_paths=potential_paths)


def analyze_behavioral_logs(log_file: str) -> UEBAResult:
    """Analyzes user activity logs to find statistical anomalies.

    This function establishes a baseline of normal activity (login hours, source IPs)
    for each user from a log file and then flags events that deviate from this baseline.
    It expects a CSV log with at least the following headers: 'timestamp', 'user', 'source_ip'.

    Args:
        log_file (str): Path to the user activity log file in CSV format.

    Returns:
        UEBAResult: A Pydantic model with a list of detected behavioral anomalies.
    """
    logger.info(f"Performing statistical UEBA on log file: {log_file}")
    if not os.path.exists(log_file):
        return UEBAResult(
            total_anomalies_found=0, error=f"Log file not found: {log_file}"
        )
    # Type aliases are now defined at the module's top level, fixing the error.

    user_ips: UserIPs = defaultdict(set)
    user_hours: UserHours = defaultdict(set)

    try:
        # --- Stage 1: Build Baselines ---

        with open(log_file, "r", encoding="utf-8") as f:
            # Use DictReader for robust column handling

            reader = csv.DictReader(f)
            logs = list(reader)

            # Check for required headers

            required_headers = ["timestamp", "user", "source_ip"]
            if reader.fieldnames and not all(
                header in reader.fieldnames for header in required_headers
            ):
                return UEBAResult(
                    total_anomalies_found=0,
                    error=f"Log file must contain headers: {', '.join(required_headers)}",
                )
            for row in logs:
                user = row["user"]
                user_ips[user].add(row["source_ip"])
                # Robustly parse timestamp to get the hour

                try:
                    # Attempt to parse ISO format timestamp (e.g., 2025-08-21T03:15:00Z)

                    hour = int(row["timestamp"].split("T")[1].split(":")[0])
                    user_hours[user].add(hour)
                except (IndexError, ValueError):
                    logger.warning(
                        f"Could not parse hour from timestamp: {row['timestamp']}. Skipping for baseline."
                    )
                    continue
        # --- Stage 2: Detect Anomalies ---

        anomalies: List[BehavioralAnomaly] = []
        for row in logs:
            user = row["user"]
            timestamp = row["timestamp"]
            source_ip = row["source_ip"]

            # Anomaly Rule 1: Login from a new IP address

            if source_ip not in user_ips[user]:
                anomalies.append(
                    BehavioralAnomaly(
                        timestamp=timestamp,
                        user=user,
                        anomaly_description=f"Login from a new source IP address: {source_ip}.",
                        severity="Medium",
                    )
                )
            # Anomaly Rule 2: Login at an unusual hour of the day

            try:
                hour = int(timestamp.split("T")[1].split(":")[0])
                if hour not in user_hours[user]:
                    anomalies.append(
                        BehavioralAnomaly(
                            timestamp=timestamp,
                            user=user,
                            anomaly_description=f"Login at an unusual time of day: {hour}:00.",
                            severity="Low",
                        )
                    )
            except (IndexError, ValueError):
                continue  # Skip anomaly check if timestamp is malformed
        return UEBAResult(total_anomalies_found=len(anomalies), anomalies=anomalies)
    except Exception as e:
        logger.error(f"Failed to process log file for UEBA: {e}", exc_info=True)
        return UEBAResult(
            total_anomalies_found=0, error=f"Failed to parse or analyze log file: {e}"
        )


# --- Integrations & Workflow ---


def submit_to_virustotal(file_path: str) -> VTSubmissionResult:
    """Submits a file to VirusTotal for analysis.

    This function uploads a file to the VirusTotal API v3. It first gets a URL
    for the upload and then POSTs the file.

    Args:
        file_path (str): The local path to the file to submit.

    Returns:
        VTSubmissionResult: A Pydantic model containing the submission result,
                            including a permalink to the analysis.
    """
    api_key = API_KEYS.virustotal_api_key
    if not api_key:
        return VTSubmissionResult(
            resource_id="",
            permalink="",
            response_code=-1,
            verbose_msg="Missing API Key.",
            error="VirusTotal API key not found.",
        )
    if not os.path.exists(file_path):
        return VTSubmissionResult(
            resource_id="",
            permalink="",
            response_code=-1,
            verbose_msg="File not found.",
            error="File not found at specified path.",
        )
    logger.info(f"Submitting {file_path} to VirusTotal.")
    headers = {"x-apikey": api_key}

    try:
        # 1. Get an upload URL

        upload_url_response = sync_client.get(
            "https://www.virustotal.com/api/v3/files/upload_url", headers=headers
        )
        upload_url_response.raise_for_status()
        upload_url = upload_url_response.json().get("data")

        # 2. Upload the file

        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = sync_client.post(upload_url, headers=headers, files=files)
            response.raise_for_status()
        analysis_id = response.json().get("data", {}).get("id")
        if not analysis_id:
            raise ValueError("Could not get analysis ID from VirusTotal response.")
        # Extract the resource ID (SHA256) from the analysis ID

        resource_id = analysis_id.split("-")[0]

        return VTSubmissionResult(
            resource_id=resource_id,
            permalink=f"https://www.virustotal.com/gui/file/{resource_id}",
            response_code=1,
            verbose_msg="Scan request successfully queued. View permalink for results.",
        )
    except Exception as e:
        logger.error(f"Failed to submit file to VirusTotal: {e}")
        return VTSubmissionResult(
            resource_id="",
            permalink="",
            response_code=-1,
            verbose_msg=str(e),
            error=f"An API error occurred: {e}",
        )


def run_workflow(workflow_file: str) -> None:
    """Runs a series of Chimera Intel commands defined in a YAML file.

    This function parses a simple YAML workflow file and executes each defined
    step as a subprocess, calling the main 'chimera' CLI.

    Args:
        workflow_file (str): Path to the YAML workflow file.
    """
    logger.info(f"Executing workflow from: {workflow_file}")
    try:
        with open(workflow_file, "r") as f:
            workflow = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to read or parse workflow file: {e}")
        return
    target = workflow.get("target")
    if not target:
        logger.error("Workflow file must define a 'target'.")
        return
    logger.info(f"Workflow target: {target}")
    steps = workflow.get("steps", [])

    for i, step in enumerate(steps):
        command_template = step.get("run")
        if command_template:
            # Substitute {target} placeholder

            full_command = f"chimera {command_template.format(target=target)}"
            console.print(
                f"\n--- [bold cyan]Running Step {i+1}:[/bold cyan] [yellow]{full_command}[/yellow] ---"
            )
            try:
                # Execute the command as a subprocess

                subprocess.run(full_command, shell=True, check=True, text=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Step {i+1} failed with exit code {e.returncode}.")
                console.print(
                    f"[bold red]Error during step {i+1}. Aborting workflow.[/bold red]"
                )
                break
    logger.info("Workflow execution finished.")


# --- Typer CLI Application ---


automation_app = typer.Typer()
connect_app = typer.Typer()


@automation_app.command("enrich-ioc")
def run_ioc_enrichment(
    iocs: List[str] = typer.Argument(
        ..., help="A list of IOCs (IPs, domains, hashes) to enrich."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Enriches Indicators of Compromise with threat intelligence."""
    results = asyncio.run(enrich_iocs(iocs))
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)


@automation_app.command("threat-model")
def run_threat_model_generation(
    domain: str = typer.Argument(..., help="The target domain to model threats for."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Generates potential attack paths based on historical scan data."""
    results = generate_threat_model(domain)
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)


@automation_app.command("ueba")
def run_ueba_analysis(
    log_file: str = typer.Argument(..., help="Path to the user activity log file."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Analyzes user activity logs for behavioral anomalies."""
    results = analyze_behavioral_logs(log_file)
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)


@automation_app.command("enrich-cve")
def run_cve_enrichment(
    cve_ids: List[str] = typer.Argument(
        ..., help="A list of CVE IDs to enrich (e.g., CVE-2021-44228)."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Enriches CVE IDs with detailed information like CVSS scores and summaries."""
    results = enrich_cves(cve_ids)
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)


@automation_app.command("workflow")
def run_automation_workflow(
    workflow_file: str = typer.Argument(..., help="Path to the YAML workflow file."),
):
    """Executes a predefined workflow of Chimera Intel commands."""
    run_workflow(workflow_file)


@connect_app.command("virustotal")
def run_vt_submission(
    file_path: str = typer.Argument(
        ..., help="Path to the file to submit to VirusTotal."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Submits a file to VirusTotal for analysis."""
    results = submit_to_virustotal(file_path)
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)
