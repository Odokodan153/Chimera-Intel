"""
ETHINT – Ethical Governance & Compliance Engine CLI.

Provides tools to audit operations for compliance with ethical and legal frameworks,
generate AI-powered Privacy Impact Reports (PIRs), and assess the trustworthiness of
information sources using a CRAAP-based scoring model. Integrates with generative AI
for analysis and produces human-readable summaries, tables, and optional JSON outputs.
"""

import logging
import json
from typing import List, Dict, Optional, Any
from datetime import datetime
import os
import importlib
import typer
from rich.console import Console
from rich.table import Table
from chimera_intel.core.schemas import (
    Operation,
    ComplianceResult,
    ComplianceViolation,
    PrivacyImpactReport,
    DataVerificationResult,
    CRAAPScore,
)
from chimera_intel.core.gemini_client import llm_call_text
from chimera_intel.core.project_manager import resolve_target
from chimera_intel.core.utils import save_or_print_results


# --- : Logger Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("ethint_audit.log"),
        logging.StreamHandler(),
    ],
)
audit_logger = logging.getLogger("ETHINT_Audit")

# --- Core Logic ---

SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

_ETHICAL_FRAMEWORKS_CACHE = None


def load_frameworks(path: Optional[str] = None) -> Dict:
    """Loads ethical frameworks from a read-only JSON file."""
    if path is None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = os.path.join(dir_path, "ethical_frameworks.json")
    try:
        with open(path, "r") as f:
            data = json.load(f)
            if not data:
                audit_logger.warning(f"Ethical frameworks file is empty: {path}")
                return {}
            return data
    except FileNotFoundError:
        audit_logger.critical(f"FATAL: Ethical frameworks file not found at {path}")
        return {}
    except json.JSONDecodeError:
        audit_logger.critical(
            f"FATAL: Could not decode JSON from ethical frameworks file: {path}"
        )
        return {}
    except Exception as e:
        audit_logger.critical(
            f"FATAL: Could not load ethical frameworks from {path}: {e}"
        )
        return {}


def get_ethical_frameworks() -> Dict:
    """Initializes and returns the cached ethical frameworks."""
    global _ETHICAL_FRAMEWORKS_CACHE
    if _ETHICAL_FRAMEWORKS_CACHE is None:
        _ETHICAL_FRAMEWORKS_CACHE = load_frameworks()
    return _ETHICAL_FRAMEWORKS_CACHE


def audit_operation(
    operation: Operation, frameworks_to_check: List[str]
) -> ComplianceResult:
    """
    Audits an operation against specified ethical and legal frameworks.
    (This function was already a 'real' implementation).
    """
    frameworks = get_ethical_frameworks()

    if not frameworks:
        audit_logger.critical("No ethical frameworks loaded. Audit cannot proceed.")
        raise RuntimeError("No ethical frameworks were loaded, cannot perform audit.")
    result = ComplianceResult(operation_id=operation.operation_id, is_compliant=True)

    def log_action(message: str):
        timestamp = datetime.now().isoformat()
        entry = f"[{timestamp}] {message}"
        result.audit_log.append(entry)
        audit_logger.info(message)

    log_action(
        f"AUDIT_START - OpID: {operation.operation_id}, Type: {operation.operation_type}"
    )

    unchecked_rules = []

    try:
        rules_module = importlib.import_module("chimera_intel.core.ethint_rules")
    except ImportError:
        log_action(
            "CRITICAL - Could not import the rules module 'chimera_intel.core.ethint_rules'."
        )
        result.is_compliant = False
        result.violations.append(
            ComplianceViolation(
                rule_id="SYSTEM-01",
                framework="System Configuration",
                severity="CRITICAL",
                description="The compliance rules engine module could not be loaded.",
            )
        )
        return result
    for framework_name in frameworks_to_check:
        framework = frameworks.get(framework_name)
        if not framework:
            log_action(f"Framework '{framework_name}' not found. Skipping.")
            continue
        framework_version = framework.get("version", "N/A")
        log_action(
            f"Checking against framework '{framework_name}' version {framework_version}"
        )

        for rule in framework.get("rules", []):
            rule_id = rule["rule_id"]
            check_function_name = "check_" + rule_id.lower().replace("-", "_")
            check_function = getattr(rules_module, check_function_name, None)

            if not check_function:
                log_action(
                    f"WARNING - OpID: {operation.operation_id}, No check function found for rule: {rule_id} (expected: {check_function_name})"
                )
                unchecked_rules.append(rule_id)
                continue
            try:
                if not check_function(operation):
                    result.is_compliant = False
                    severity = rule.get("severity", "UNKNOWN")
                    violation = ComplianceViolation(
                        rule_id=rule_id,
                        framework=f"{framework_name} (v{framework_version})",
                        severity=severity,
                        description=rule["description"],
                    )
                    result.violations.append(violation)
                    log_action(
                        f"VIOLATION - OpID: {operation.operation_id}, Rule: {rule_id}, Severity: {severity}"
                    )
            except Exception as e:
                log_action(
                    f"ERROR - OpID: {operation.operation_id}, Rule: {rule_id} failed to execute: {e}"
                )
    if unchecked_rules:
        result.is_compliant = False
        description = f"Compliance could not be fully verified. Missing checks for rules: {', '.join(unchecked_rules)}"
        result.violations.append(
            ComplianceViolation(
                rule_id="SYSTEM-02",
                framework="Audit Integrity",
                severity="CRITICAL",
                description=description,
            )
        )
        log_action(
            f"NON_COMPLIANT - OpID: {operation.operation_id}, Missing rule implementations: {', '.join(unchecked_rules)}"
        )
    decision = "COMPLIANT" if result.is_compliant else "NON_COMPLIANT"
    log_action(f"AUDIT_END - OpID: {operation.operation_id}, Decision: {decision}")

    return result


def generate_privacy_impact_report(
    target: str, data: List[Dict[str, Any]], justification: str
) -> PrivacyImpactReport:
    """
    Generates a Privacy Impact Report (PIR) for a target based on collected data.
    Uses the project's generative AI model to assess risk and proportionality.

    Args:
        target (str): The person or group being assessed.
        data (List[Dict[str, Any]]): A list of data objects (e.g., scan results) collected.
        justification (str): The analyst's justification for the investigation.

    Returns:
        PrivacyImpactReport: The generated report.
    """
    audit_logger.info(f"Generating Privacy Impact Report for target: {target}")
    try:
        # Summarize the collected data to send to the LLM
        data_categories = set()
        pii_found = False
        for item in data:
            module = item.get("module", "unknown")
            data_categories.add(module)
            if "compliance-check" in module:
                if item.get("total_findings", 0) > 0:
                    pii_found = True
        
        if pii_found:
            data_categories.add("PII_Detected")

        data_summary = f"Data has been collected from the following modules: {', '.join(data_categories)}. Justification: {justification}"

        prompt = f"""
        You are an ethical governance and privacy expert. Analyze the following intelligence operation and generate a Privacy Impact Report (PIR).
        
        Target: "{target}"
        Data Collected Summary: "{data_summary}"
        Justification provided: "{justification}"

        Your tasks:
        1.  Write a brief, expert summary (2-3 sentences) of the potential privacy impact of this operation.
        2.  List the *categories* of data collected (e.g., "Public Web Records", "PII (Redacted)", "Social Media Posts", "Court Dockets").
        3.  List the most significant potential privacy risks (e.g., "Re-identification", "Chilling effect", "Inaccurate profiling", "Unjustified surveillance").
        4.  Write a proportionality assessment (2-3 sentences): Is the data collection described (modules: {', '.join(data_categories)}) proportionate to the stated justification ("{justification}")? Be critical.
        
        Return ONLY a valid JSON object in the following format. Do not include markdown ticks or any other text.
        {{
            "summary": "...",
            "data_collected": ["...", "..."],
            "potential_risks": ["...", "..."],
            "proportionality_assessment": "..."
        }}
        """

        response_text = llm_call_text(prompt, max_tokens=1024)
        if not response_text:
            raise Exception("LLM call returned no text.")
            
        # Clean the response to ensure it's valid JSON
        json_str = response_text.strip().lstrip("```json").rstrip("```")
        report_data = json.loads(json_str)

        return PrivacyImpactReport(
            target=target,
            justification=justification,
            summary=report_data.get("summary", "N/A"),
            data_collected=report_data.get("data_collected", []),
            potential_risks=report_data.get("potential_risks", []),
            proportionality_assessment=report_data.get("proportionality_assessment", "N/A"),
        )
    except Exception as e:
        audit_logger.error(f"Failed to generate Privacy Impact Report: {e}")
        return PrivacyImpactReport(
            target=target,
            justification=justification,
            error=f"An error occurred: {e}",
            summary="",
            proportionality_assessment="",
        )


def assess_source_trust(
    source_identifier: str, source_content_snippet: str
) -> DataVerificationResult:
    """
    Implements a dynamic scoring system (CRAAP model) using the project's
    generative AI model.

    Args:
        source_identifier (str): The URL, domain, or name of the source.
        source_content_snippet (str): A snippet of content from the source.

    Returns:
        DataVerificationResult: A report with the CRAAP score and reliability.
    """
    audit_logger.info(f"Assessing source trust for: {source_identifier}")
    try:
        prompt = f"""
        You are an intelligence analyst specializing in source verification. Assess the following information source using the CRAAP model (Currency, Relevance, Authority, Accuracy, Purpose).
        Provide a score from 0.0 to 5.0 for each category, with justification.
        
        Source Identifier: "{source_identifier}"
        Source Content Snippet: "{source_content_snippet[:1500]}"

        Your tasks:
        1.  Score Currency (0.0-5.0): How recent is the information? (5.0 = this week, 0.0 = >10 years)
        2.  Score Relevance (0.0-5.0): How relevant is this information to an intelligence objective? (5.0 = highly relevant, 0.0 = irrelevant)
        3.  Score Authority (0.0-5.0): What is the authority/reputation of the source? (5.0 = major intl. news/gov, 3.0 = industry blog, 1.0 = fringe forum)
        4.  Score Accuracy (0.0-5.0): Can the information be verified? Is it well-sourced or blatant opinion? (5.0 = verifiable facts, 1.0 = unsourced opinion)
        5.  Score Purpose (0.0-5.0): What is the purpose? (5.0 = objective reporting, 3.0 = marketing, 1.0 = propaganda/disinformation)
        
        Return ONLY a valid JSON object in the following format. Do not include markdown ticks or any other text.
        {{
            "currency": 0.0,
            "relevance": 0.0,
            "authority": 0.0,
            "accuracy": 0.0,
            "purpose": 0.0
        }}
        """
        
        response_text = llm_call_text(prompt, max_tokens=512)
        if not response_text:
            raise Exception("LLM call returned no text.")

        # Clean the response to ensure it's valid JSON
        json_str = response_text.strip().lstrip("```json").rstrip("```")
        craap_data = json.loads(json_str)
        craap_score = CRAAPScore.model_validate(craap_data)

        # Calculate overall score and reliability
        scores = craap_data.values()
        overall_score = sum(scores) / len(scores) if scores else 0.0
        reliability_score = overall_score * 20  # Convert 0-5 scale to 0-100

        return DataVerificationResult(
            source_identifier=source_identifier,
            reliability_score=reliability_score,
            craap_assessment=craap_score,
            last_verified=datetime.now(),
        )

    except Exception as e:
        audit_logger.error(f"Failed to assess source trust: {e}")
        return DataVerificationResult(
            source_identifier=source_identifier,
            reliability_score=0.0,
            error=f"An error occurred: {e}",
        )


# --- CLI Integration ---


app = typer.Typer(
    name="ethint",
    help="Ethical Governance & Compliance Engine.",
    no_args_is_help=True,
)


@app.command("audit")
def run_audit(
    operation_json_file: str = typer.Argument(
        ..., help="Path to a JSON file representing the operation."
    ),
    frameworks: List[str] = typer.Option(
        ["data_privacy_gdpr", "rules_of_engagement_default"],
        help="Frameworks to audit against.",
    ),
    severity_level: str = typer.Option(
        "LOW",
        "--severity-level",
        "-s",
        help="Minimum severity level to display (LOW, MEDIUM, HIGH, CRITICAL).",
    ),
):
    """Audits a proposed operation from a file for ethical and legal compliance."""
    console = Console()

    min_severity = SEVERITY_LEVELS.get(severity_level.upper())
    if min_severity is None:
        console.print(
            f"[bold red]Invalid severity level '{severity_level}'. Choose from LOW, MEDIUM, HIGH, CRITICAL.[/]"
        )
        raise typer.Exit(code=4)
    try:
        with open(operation_json_file, "r") as f:
            op_data = json.load(f)
        operation = Operation(**op_data)
    except Exception as e:
        console.print(
            f"[bold red]Error parsing operation file '{operation_json_file}':[/] {e}"
        )
        raise typer.Exit(code=2)
    try:
        result = audit_operation(operation, frameworks)
    except RuntimeError as e:
        console.print(f"[bold red]Audit failed to run:[/] {e}")
        raise typer.Exit(code=3)
    if result.is_compliant:
        console.print(
            f"[bold green]Operation '{operation.operation_id}' is COMPLIANT.[/]"
        )
    else:
        console.print(
            f"[bold red]Operation '{operation.operation_id}' is NON-COMPLIANT.[/]"
        )

        filtered_violations = [
            v
            for v in result.violations
            if SEVERITY_LEVELS.get(v.severity.upper(), 0) >= min_severity
        ]

        if filtered_violations:
            table = Table(
                title=f"Compliance Violations (Severity >= {severity_level.upper()})"
            )
            table.add_column("Framework", style="yellow")
            table.add_column("Rule ID", style="cyan")
            table.add_column("Severity", style="magenta")
            table.add_column("Description", style="red")

            for v in filtered_violations:
                table.add_row(v.framework, v.rule_id, v.severity, v.description)
            console.print(table)
        else:
            console.print(
                f"[yellow]No violations found at or above severity level '{severity_level.upper()}'.[/]"
            )
    console.print("\n[bold]Audit Log:[/bold]")
    for log in result.audit_log:
        console.print(f"- {log}")
    if not result.is_compliant:
        raise typer.Exit(code=1)


@app.command("privacy-impact-report")
def run_privacy_impact_report(
    target: Optional[str] = typer.Option(
        None,
        "--target",
        "-t",
        help="The target (person or group). Uses active project company name if not provided.",
    ),
    justification: str = typer.Option(
        ...,
        "--justification",
        "-j",
        prompt="Please provide the justification for this investigation",
        help="The analyst's justification for the investigation.",
    ),
    scan_ids: List[int] = typer.Option(
        ...,
        "--scan-id",
        "-i",
        help="List of scan IDs from the DB to include in the assessment.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save report to a JSON file."
    ),
):
    """Generates an AI-powered Privacy Impact Report for an investigation."""
    console = Console()
    try:
        from .database import get_scan_from_db
        import json

        if not target:
            target = resolve_target(target, required_assets=["company_name"])
        
        console.print(f"Generating Privacy Impact Report for target: {target}")
        
        collected_data = []
        for scan_id in scan_ids:
            scan = get_scan_from_db(scan_id)
            if not scan:
                console.print(f"[yellow]Warning: Scan ID {scan_id} not found. Skipping.[/]")
                continue
            scan_data = json.loads(scan.result)
            # Add module info for context
            scan_data["module"] = scan.module
            collected_data.append(scan_data)

        if not collected_data:
            console.print("[bold red]Error: No valid scan data found. Cannot generate report.[/]")
            raise typer.Exit(code=1)

        result = generate_privacy_impact_report(target, collected_data, justification)
        
        if result.error:
            console.print(f"[bold red]Error generating report: {result.error}[/]")
            raise typer.Exit(code=1)

        # Print a summary
        console.print("\n[bold]Privacy Impact Report Summary[/]")
        console.print(f"[bold]Target:[/bold] {result.target}")
        console.print(f"[bold]Justification:[/bold] {result.justification}")
        console.print(f"\n[bold]AI Summary:[/bold]\n{result.summary}")
        console.print(f"\n[bold]Proportionality Assessment:[/bold]\n{result.proportionality_assessment}")
        
        console.print("\n[bold]Data Collected:[/bold]")
        for cat in result.data_collected:
            console.print(f"- {cat}")
            
        console.print("\n[bold]Potential Risks:[/bold]")
        for risk in result.potential_risks:
            console.print(f"- {risk}")

        if output_file:
            save_or_print_results(result.model_dump(exclude_none=True), output_file)

    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/]", err=True)
        raise typer.Exit(code=1)


@app.command("source-trust-model")
def run_source_trust_model(
    source_identifier: str = typer.Argument(
        ..., help="The source URL, domain, or name (e.g., 'fringe-blog.com')."
    ),
    content_snippet: str = typer.Option(
        ...,
        "--content",
        "-c",
        prompt="Provide a short snippet of content from the source",
        help="A snippet of text from the source to help assessment.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save report to a JSON file."
    ),
):
    """Assigns an AI-powered, quantifiable trust score (CRAAP model) to a data source."""
    console = Console()
    try:
        console.print(f"Assessing source trust for [bold]{source_identifier}[/]...")
        result = assess_source_trust(source_identifier, content_snippet)
        
        if result.error:
            console.print(f"[bold red]Error assessing source: {result.error}[/]")
            raise typer.Exit(code=1)
            
        console.print(f"\n[bold]Source Trust Assessment for:[/bold] {result.source_identifier}")
        console.print(f"[bold]Overall Reliability Score:[/bold] {result.reliability_score:.2f} / 100.0")

        if result.craap_assessment:
            table = Table(title="CRAAP Model Breakdown (Score / 5.0)")
            table.add_column("Metric", style="cyan")
            table.add_column("Score", style="magenta")
            
            craap = result.craap_assessment
            table.add_row("Currency", f"{craap.currency:.2f}")
            table.add_row("Relevance", f"{craap.relevance:.2f}")
            table.add_row("Authority", f"{craap.authority:.2f}")
            table.add_row("Accuracy", f"{craap.accuracy:.2f}")
            table.add_row("Purpose", f"{craap.purpose:.2f}")
            
            console.print(table)

        if output_file:
            save_or_print_results(result.model_dump(exclude_none=True), output_file)

    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/]", err=True)
        raise typer.Exit(code=1)