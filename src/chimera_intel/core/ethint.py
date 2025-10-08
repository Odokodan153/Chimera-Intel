import logging
import json
from typing import List, Dict, Optional
from .schemas import Operation, ComplianceResult, ComplianceViolation
import typer
from rich.console import Console
from rich.table import Table

# --- : Logger Configuration ---
# Configure the logger to write to a file, ensuring all audits are recorded.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("ethint_audit.log"),
        logging.StreamHandler() # Also log to console for immediate feedback
    ]
)
audit_logger = logging.getLogger("ETHINT_Audit")


# --- Pydantic Models ---



# --- Core Logic ---

def load_frameworks(path: str = "src/chimera_intel/core/ethical_frameworks.json") -> Dict:
    """Loads ethical frameworks from a read-only JSON file."""
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        audit_logger.critical(f"FATAL: Could not load ethical frameworks from {path}: {e}")
        return {}

ETHICAL_FRAMEWORKS = load_frameworks()

def audit_operation(operation: Operation, frameworks_to_check: List[str]) -> ComplianceResult:
    """Audits an operation against specified ethical and legal frameworks."""
    result = ComplianceResult(operation_id=operation.operation_id, is_compliant=True)

    log_entry = f"AUDIT_START - OpID: {operation.operation_id}, Type: {operation.operation_type}"
    result.audit_log.append(log_entry)
    audit_logger.info(log_entry)

    for framework_name in frameworks_to_check:
        framework = ETHICAL_FRAMEWORKS.get(framework_name)
        if not framework:
            result.audit_log.append(f"Framework '{framework_name}' not found. Skipping.")
            continue
        
        framework_version = framework.get("version", "N/A")
        result.audit_log.append(f"Checking against framework '{framework_name}' version {framework_version}")

        for rule in framework.get("rules", []):
            # Use `eval` for safer, dynamic condition checking from JSON
            # This is safer than lambdas with missing attributes. `operation` is the only context.
            try:
                condition_met = eval(rule["condition"], {"__builtins__": {}}, {"operation": operation})
                if not condition_met:
                    result.is_compliant = False
                    violation = ComplianceViolation(
                        rule_id=rule["rule_id"],
                        framework=f"{framework_name} (v{framework_version})",
                        severity=rule.get("severity", "UNKNOWN"),
                        description=rule["description"]
                    )
                    result.violations.append(violation)
                    log_entry = f"VIOLATION - OpID: {operation.operation_id}, Rule: {rule['rule_id']}, Severity: {violation.severity}"
                    result.audit_log.append(log_entry)
                    audit_logger.warning(log_entry)
            except Exception as e:
                log_entry = f"ERROR - OpID: {operation.operation_id}, Rule: {rule['rule_id']} failed to execute: {e}"
                result.audit_log.append(log_entry)
                audit_logger.error(log_entry)


    decision = "COMPLIANT" if result.is_compliant else "NON_COMPLIANT"
    log_entry = f"AUDIT_END - OpID: {operation.operation_id}, Decision: {decision}"
    result.audit_log.append(log_entry)
    audit_logger.info(log_entry)
    
    return result

# --- CLI Integration ---

app = typer.Typer(
    name="ethint",
    help="Ethical Governance & Compliance Engine.",
    no_args_is_help=True,
)

@app.command("audit")
def run_audit(
    operation_json_file: str = typer.Argument(..., help="Path to a JSON file representing the operation."),
    frameworks: List[str] = typer.Option(["data_privacy_gdpr", "rules_of_engagement_default"], help="Frameworks to audit against."),
):
    """Audits a proposed operation from a file for ethical and legal compliance."""
    console = Console()
    try:
        with open(operation_json_file, 'r') as f:
            op_data = json.load(f)
        operation = Operation(**op_data)
    except Exception as e:
        console.print(f"[bold red]Error parsing operation file '{operation_json_file}':[/] {e}")
        return

    result = audit_operation(operation, frameworks)

    if result.is_compliant:
        console.print(f"[bold green]Operation '{operation.operation_id}' is COMPLIANT.[/]")
    else:
        console.print(f"[bold red]Operation '{operation.operation_id}' is NON-COMPLIANT.[/]")
        
        table = Table(title="Compliance Violations")
        table.add_column("Framework", style="yellow")
        table.add_column("Rule ID", style="cyan")
        table.add_column("Severity", style="magenta")
        table.add_column("Description", style="red")

        for v in result.violations:
            table.add_row(v.framework, v.rule_id, v.severity, v.description)
        console.print(table)

    console.print("\n[bold]Audit Log:[/bold]")
    for log in result.audit_log:
        console.print(f"- {log}")