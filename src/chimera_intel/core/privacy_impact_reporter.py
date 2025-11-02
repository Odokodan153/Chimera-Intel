"""
Module for Privacy Impact Reporter (GRC).

Generates formal reports on the potential PII or compliance violations
in a given dataset, leveraging the EthicalGuardrails module.
"""

import typer
import logging
import json
from typing import Optional, Dict, Any, List
from chimera_intel.core.schemas import PrivacyImpactReport
from datetime import datetime, timezone
import hashlib
from .ethical_guardrails import EthicalGuardrails
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .project_manager import resolve_target

logger = logging.getLogger(__name__)
privacy_impact_reporter_app = typer.Typer()

# Initialize the re-used guardrail
guardrail = EthicalGuardrails()

def generate_privacy_impact_report(
    documents: List[Dict[str, Any]], target: str
) -> PrivacyImpactReport:
    """
    Scans a list of documents for PII and generates a formal impact report.
    """
    logger.info(f"Generating Privacy Impact Report for target {target}")
    
    total_scanned = 0
    docs_with_pii = 0
    violation_counts = {}
    all_violations = []

    for i, doc in enumerate(documents):
        content = doc.get("content", "")
        if not content:
            continue
        
        total_scanned += 1
        # Re-use the ethical guardrail check
        pii_results = guardrail.check_content_for_pii(content)
        
        if pii_results:
            docs_with_pii += 1
            doc_hint = content[:50] + "..."
            
            for pii_type, pii_value in pii_results.items():
                violation_counts[pii_type] = violation_counts.get(pii_type, 0) + 1
                all_violations.append({
                    "document_index": i,
                    "document_hint": doc_hint,
                    "pii_type": pii_type,
                    "pii_value_redacted": pii_value  # Assume check_content returns redacted
                })

    # Determine risk level
    if docs_with_pii == 0:
        risk = "Low"
        mitigations = ["No PII detected. No mitigation required."]
    elif (docs_with_pii / total_scanned) < 0.1:
        risk = "Medium"
        mitigations = ["PII detected in <10% of documents.", "Review and manually redact.", "Flag data for restricted access."]
    else:
        risk = "High"
        mitigations = ["PII detected in >10% of documents.", "Do not use data until fully anonymized.", "Apply strict access controls.", "Purge raw data from non-secure logs."]

    report_id = f"PIR-{hashlib.md5(f'{target}{datetime.now(timezone.utc).isoformat()}'.encode()).hexdigest()}"

    return PrivacyImpactReport(
        report_id=report_id,
        target=target,
        total_documents_scanned=total_scanned,
        documents_with_pii=docs_with_pii,
        overall_risk_level=risk,
        violation_summary=violation_counts,
        mitigation_steps=mitigations,
        violations=all_violations
    )


@privacy_impact_reporter_app.command("run")
def run_privacy_report_cli(
    target: Optional[str] = typer.Argument(
        None, help="The target/topic being analyzed. Uses active project if not provided."
    ),
    input_file: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Path to a JSON file containing a list of objects, "
             "each with a 'content' key.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Generates a Privacy Impact Report by scanning documents for PII.
    """
    target_name = resolve_target(target, required_assets=[])

    try:
        with open(input_file, "r") as f:
            documents = json.load(f)
        if not isinstance(documents, list):
            raise ValueError("Input file must contain a JSON list.")
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/] Input file not found at '{input_file}'")
        raise typer.Exit(code=1)
    except (json.JSONDecodeError, ValueError) as e:
        console.print(f"[bold red]Error:[/] Invalid JSON in file '{input_file}': {e}")
        raise typer.Exit(code=1)

    with console.status(
        f"[bold cyan]Generating Privacy Impact Report for {target_name}...[/bold cyan]"
    ):
        results_model = generate_privacy_impact_report(documents, target_name)

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_name, module="privacy_impact_report", data=results_dict
    )