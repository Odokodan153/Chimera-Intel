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
import json
from collections import defaultdict
from typing import List, Optional, Set, DefaultDict
from datetime import datetime, timezone
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
    DataFeedStatus,
    DataQualityReport,
    ThreatIntelResult,
    Event,
)
import json
from .schemas import Event
from .correlation_engine import AlertPrioritizationEngine, execute_automation_pipelines 
from .config_loader import load_config
from .utils import save_or_print_results, console
from .config_loader import API_KEYS, load_config
from .http_client import sync_client
from .threat_intel import get_threat_intel_otx
from .database import get_aggregated_data_for_target

# --- IMPORTS FOR WORKFLOW ---
from .advanced_media_analysis import SyntheticMediaAudit
from .response import ACTION_MAP # Import the non-mock map
# --- END NEW IMPORTS ---

# --- NEW: Import new engines and schemas ---
from .correlation_engine import AlertPrioritizationEngine, AutomationPipeline


UserIPs = DefaultDict[str, Set[str]]
UserHours = DefaultDict[str, Set[int]]


logger = logging.getLogger(__name__)


# --- Data Enrichment ---
# (enrich_iocs and enrich_cves functions remain unchanged)
async def enrich_iocs(iocs: List[str]) -> EnrichmentResult:
    """Enriches Indicators of Compromise (IOCs) with threat intelligence from OTX."""
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
    """Enriches a list of CVE IDs with details from the Vulners API."""
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
# (generate_threat_model and analyze_behavioral_logs functions remain unchanged)
def generate_threat_model(domain: str) -> ThreatModelResult:
    """Analyzes aggregated scan data to generate potential attack paths."""
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
    """Analyzes user activity logs to find statistical anomalies."""
    logger.info(f"Performing statistical UEBA on log file: {log_file}")
    if not os.path.exists(log_file):
        return UEBAResult(
            total_anomalies_found=0, error=f"Log file not found: {log_file}"
        )
    user_ips: UserIPs = defaultdict(set)
    user_hours: UserHours = defaultdict(set)

    try:
        # --- Stage 1: Build Baselines ---
        with open(log_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            logs = list(reader)

            required_headers = ["timestamp", "user", "source_ip"]
            if not reader.fieldnames or not all(
                h in reader.fieldnames for h in required_headers
            ):
                return UEBAResult(
                    total_anomalies_found=0,
                    error=f"Log file must contain headers: {', '.join(required_headers)}",
                )
            # Establish baseline from the first half of the logs
            baseline_logs = logs[: len(logs) // 2]
            for row in baseline_logs:
                user = row["user"]
                user_ips[user].add(row["source_ip"])
                try:
                    hour = int(row["timestamp"].split("T")[1].split(":")[0])
                    user_hours[user].add(hour)
                except (IndexError, ValueError):
                    logger.warning(
                        f"Could not parse hour from timestamp: {row['timestamp']}. Skipping for baseline."
                    )
                    continue
        # --- Stage 2: Detect Anomalies in the second half ---
        anomalies: List[BehavioralAnomaly] = []
        detection_logs = logs[len(logs) // 2 :]
        for row in detection_logs:
            user = row["user"]
            timestamp = row["timestamp"]
            source_ip = row["source_ip"]

            if source_ip not in user_ips[user]:
                anomalies.append(
                    BehavioralAnomaly(
                        timestamp=timestamp,
                        user=user,
                        anomaly_description=f"Login from a new source IP address: {source_ip}.",
                        severity="Medium",
                    )
                )
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
                continue
        return UEBAResult(total_anomalies_found=len(anomalies), anomalies=anomalies)
    except Exception as e:
        logger.error(f"Failed to process log file for UEBA: {e}", exc_info=True)
        return UEBAResult(
            total_anomalies_found=0, error=f"Failed to parse or analyze log file: {e}"
        )


# --- Integrations & Workflow ---
# (submit_to_virustotal and run_workflow functions remain unchanged)
def submit_to_virustotal(file_path: str) -> VTSubmissionResult:
    """Submits a file to VirusTotal for analysis."""
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
    """Runs a series of Chimera Intel commands defined in a YAML file."""
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

# --- Data Quality Governance ---
# (check_data_feed_quality function remains unchanged)
def check_data_feed_quality() -> DataQualityReport:
    """
    Runs real checks on external API feeds for availability,
    freshness, and schema integrity.
    """
    logger.info("Checking data quality of external API feeds...")
    
    statuses: List[DataFeedStatus] = []
    feeds_down = 0
    now_utc = datetime.now(timezone.utc)

    # --- 1. OTX API Check ---
    otx_key = API_KEYS.otx_api_key
    otx_status = DataFeedStatus(feed_name="OTX API", last_checked=now_utc.isoformat(), status="DOWN")
    if not otx_key:
        otx_status.message = "API key is missing."
        feeds_down += 1
    else:
        try:
            response = sync_client.get(
                "https://otx.alienvault.com/api/v1/indicators/ip/8.8.8.8",
                headers={"X-OTX-API-KEY": otx_key},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            # Real Schema Validation
            ThreatIntelResult.model_validate(data) # Use Pydantic schema
            
            # Real Freshness Check
            modified_str = data.get('modified')
            if modified_str:
                modified_time = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
                if (now_utc - modified_time).days > 7:
                    otx_status.status = "DEGRADED"
                    otx_status.message = f"Data is stale (last modified {modified_time.date()})."
                    feeds_down += 1
                else:
                    otx_status.status = "UP"
                    otx_status.message = f"OK (Responded in {response.elapsed.total_seconds():.2f}s)"
            else:
                otx_status.status = "UP"
                otx_status.message = f"OK (Responded in {response.elapsed.total_seconds():.2f}s)"

        except Exception as e:
            otx_status.message = f"Check failed: {e}"
            feeds_down += 1
    statuses.append(otx_status)

    # --- 2. Vulners API Check ---
    vulners_key = API_KEYS.vulners_api_key
    vulners_status = DataFeedStatus(feed_name="Vulners API", last_checked=now_utc.isoformat(), status="DOWN")
    if not vulners_key:
        vulners_status.message = "API key is missing."
        feeds_down += 1
    else:
        try:
            response = sync_client.post(
                "https://vulners.com/api/v3/search/id/",
                json={"apiKey": vulners_key, "id": ["CVE-2021-44228"]},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get("result") != "OK" or "data" not in data or "documents" not in data["data"]:
                vulners_status.status = "DEGRADED"
                vulners_status.message = "Schema mismatch in response."
                feeds_down += 1
            else:
                vulners_status.status = "UP"
                vulners_status.message = f"OK (Responded in {response.elapsed.total_seconds():.2f}s)"
                
        except Exception as e:
            vulners_status.message = f"Check failed: {e}"
            feeds_down += 1
    statuses.append(vulners_status)

    # --- 3. VirusTotal API Check ---
    vt_key = API_KEYS.virustotal_api_key
    vt_status = DataFeedStatus(feed_name="VirusTotal API", last_checked=now_utc.isoformat(), status="DOWN")
    if not vt_key:
        vt_status.message = "API key is missing."
        feeds_down += 1
    else:
        try:
            response = sync_client.get(
                "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                headers={"x-apikey": vt_key},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            if "data" not in data or "attributes" not in data["data"] or "id" not in data["data"]:
                vt_status.status = "DEGRADED"
                vt_status.message = "Schema mismatch in response."
                feeds_down += 1
            else:
                vt_status.status = "UP"
                vt_status.message = f"OK (Responded in {response.elapsed.total_seconds():.2f}s)"

        except Exception as e:
            vt_status.message = f"Check failed: {e}"
            feeds_down += 1
    statuses.append(vt_status)
    

    return DataQualityReport(
        feeds_checked=len(statuses),
        feeds_down=feeds_down,
        statuses=statuses
    )

# --- Typer CLI Application ---

automation_app = typer.Typer()

# (Existing commands: enrich-ioc, threat-model, ueba, enrich-cve, workflow)
#
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


# --- NEW: ALERT PRIORITIZATION CLI COMMAND ---

@automation_app.command("prioritize-event")
def run_prioritize_event(
    event_json: str = typer.Argument(
        ...,
        help="A JSON string representing the event to prioritize.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    (NEW) Runs a raw event through the Alert Prioritization Engine.
    """
    try:
        event_data = json.loads(event_json)
        # Fill in required Event fields if not provided
        event_data.setdefault("source", "manual_cli")
        event_data.setdefault("details", {})
        event = Event.model_validate(event_data)
    except Exception as e:
        console.print(f"[bold red]Error parsing event JSON: {e}[/bold red]")
        raise typer.Exit(code=1)

    # Load config to get prioritization weights
    config = load_config()
    engine = AlertPrioritizationEngine(config.get("prioritization_weights", {}))
    
    result = engine.prioritize_alert(event)
    save_or_print_results(result.model_dump(), output_file)


# --- NEW: AUTOMATION PIPELINE (IFTTT) CLI COMMANDS ---

@automation_app.command("pipeline-list")
def run_pipeline_list(
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    (NEW) Lists all configured Automation Pipelines (IFTTT workflows).
    """
    config = load_config()
    pipelines = config.get("automation_pipelines", {}).get("pipelines", [])
    if not pipelines:
        console.print("[yellow]No Automation Pipelines configured.[/yellow]")
        return
        
    save_or_print_results(pipelines, output_file)


# (A 'pipeline-create' command would require modifying the config.yaml on disk,
# which is a more complex operation. 'pipeline-list' provides visibility.)


# --- NON-MOCKED WORKFLOW COMMAND ---
# (deception-response-workflow function remains unchanged)
@automation_app.command("deception-response-workflow")
def run_deception_response_workflow(
    media_file: str = typer.Argument(..., help="Path to the suspected deepfake media file."),
    target_executive: str = typer.Argument(..., help="Name of the executive or asset being targeted."),
    confidence_threshold: float = typer.Option(0.7, "--threshold", "-t", help="Confidence threshold (0.0-1.0) to trigger the response."),
):
    """
    Automated workflow to respond to a high-confidence deepfake detection.
    
    Verifies the media file and, if it exceeds the threshold,
    executes a 4-step *REAL* (non-mocked) response:
    1. Legal Snapshot (Logs to 'legal_hold.log')
    2. Generate Debunking Script (Saves to .txt)
    3. Platform Takedown Request (Checks keys, attempts POST)
    4. Internal Threat Warning (Attempts POST to Slack)
    """
    console.print(f"[bold cyan]--- Starting Deception Response Workflow ---[/bold cyan]")
    
    if not os.path.exists(media_file):
        console.print(f"[bold red]Error:[/bold red] Media file not found at {media_file}")
        raise typer.Exit(code=1)
        
    console.print(f"Analyzing media file: {media_file}...")
    
    try:
        audit_result = SyntheticMediaAudit(media_file).analyze()
    except Exception as e:
        console.print(f"[bold red]Error during media analysis:[/bold red] {e}")
        raise typer.Exit(code=1)

    confidence = round(audit_result.confidence, 2)
    console.print(f"Deepfake detection confidence: {confidence}")

    if confidence >= confidence_threshold:
        console.print(f"[bold red]CONFIRMED:[/bold red] High-confidence deepfake detected. (Confidence: {confidence})")
        console.print("[bold yellow]Executing automated response...[/bold yellow]")
        
        # Create a details DICT to pass to the real action functions
        details = {
            "media_file": os.path.abspath(media_file),
            "target": target_executive,
            "confidence": confidence,
            "suspected_model": audit_result.suspected_origin_model
        }
        
        # Manually call the (real) actions from the response module
        try:
            ACTION_MAP['legal_notification_snapshot'](details)
            ACTION_MAP['generate_debunking_script'](details)
            ACTION_MAP['platform_takedown_request'](details)
            ACTION_MAP['internal_threat_warning'](details)
        except KeyError as e:
            console.print(f"[bold red]Workflow Action Error:[/bold red] Action {e} not found in response.ACTION_MAP.")
        except Exception as e:
            console.print(f"[bold red]Workflow Execution Error:[/bold red] {e}")
            
        console.print("[bold green]--- Deception Response Workflow Completed ---[/bold green]")
        
    else:
        console.print(f"[bold green]INFO:[/bold green] Media confidence ({confidence}) is below threshold ({confidence_threshold}).")
        console.print("[bold]No automated response actions taken.[/bold]")
        
# --- END NEW WORKFLOW ---


# (Existing commands: virustotal, check-feeds)
@automation_app.command("virustotal")
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


@automation_app.command("check-feeds")
def run_data_quality_check(
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Checks the status, freshness, and schema integrity of all external data feeds."""
    results = check_data_feed_quality() # Fixed recursive call
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)
    
    if results.feeds_down > 0:
        console.print(f"[bold red]Warning: {results.feeds_down} data feed(s) are down or degraded.[/bold red]")
        raise typer.Exit(code=1)
    else:
        console.print("[bold green]All data feeds are UP and responding correctly.[/bold green]")

@automation_app.command("pipeline-run-trigger") # <-- NEW COMMAND
def run_pipeline_trigger(
    event_json: str = typer.Argument(
        ...,
        help="A JSON string representing the event to trigger pipelines.",
    ),
):
    """
    (NEW) Runs a raw event through the Autonomous Workflow Triggers.
    
    This will check the event against all configured pipelines
    in config.yaml and run any matched actions (e.g., covert scans).
    """
    try:
        event_data = json.loads(event_json)
        event = Event.model_validate(event_data)
    except Exception as e:
        console.print(f"[bold red]Error parsing event JSON: {e}[/bold red]")
        raise typer.Exit(code=1)

    # The config is loaded automatically by the engine via CONFIG
    execute_automation_pipelines(event)
    console.print(f"[bold green]Autonomous trigger check complete for {event.target}.[/bold green]")