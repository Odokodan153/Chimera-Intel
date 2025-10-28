import logging
import json
from typing import List, Dict, Optional
from .schemas import Operation, ComplianceResult, ComplianceViolation
import typer
from rich.console import Console
from rich.table import Table
import importlib
from datetime import datetime
import os

# --- : Logger Configuration ---
# Configure the logger to write to a file, ensuring all audits are recorded.


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("ethint_audit.log"),
        logging.StreamHandler(),  # Also log to console for immediate feedback
    ],
)
audit_logger = logging.getLogger("ETHINT_Audit")

# --- Core Logic ---

# Maps severity names to a numerical level for filtering.


SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# FIX: Global cache variable for lazy loading
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

# FIX: Function to perform lazy loading/caching
def get_ethical_frameworks() -> Dict:
    """Initializes and returns the cached ethical frameworks."""
    global _ETHICAL_FRAMEWORKS_CACHE
    if _ETHICAL_FRAMEWORKS_CACHE is None:
        _ETHICAL_FRAMEWORKS_CACHE = load_frameworks()
    return _ETHICAL_FRAMEWORKS_CACHE

# FIX: Removed the module-level execution to allow testing frameworks to properly mock dependencies.
# ETHICAL_FRAMEWORKS = load_frameworks()


def audit_operation(
    operation: Operation, frameworks_to_check: List[str]
) -> ComplianceResult:
    """
    Audits an operation against specified ethical and legal frameworks.

    Args:
        operation: The operation object to be audited.
        frameworks_to_check: A list of framework names to check against.

    Returns:
        A ComplianceResult object containing the audit findings.

    Raises:
        RuntimeError: If the ethical frameworks cannot be loaded.
    """
    # FIX: Use the getter function to ensure frameworks are loaded correctly for testing
    frameworks = get_ethical_frameworks() 
    
    if not frameworks:
        audit_logger.critical("No ethical frameworks loaded. Audit cannot proceed.")
        raise RuntimeError("No ethical frameworks were loaded, cannot perform audit.")
    result = ComplianceResult(operation_id=operation.operation_id, is_compliant=True)

    def log_action(message: str):
        """Adds a timestamped message to the audit log."""
        timestamp = datetime.now().isoformat()
        entry = f"[{timestamp}] {message}"
        result.audit_log.append(entry)
        # Also log to the file logger, which adds its own timestamp.

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
        # FIX: Use the local 'frameworks' variable instead of the old global one
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

        # Filter violations based on the specified severity level

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