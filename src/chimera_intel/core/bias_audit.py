"""
Module for Bias and Gap Analysis (Bias Audit).

A meta-analysis tool that runs on the platform's own outputs
(reports, graphs) to detect potential analyst or collection bias
by checking for data gaps, confirmation bias, or over-reliance
on a single source.
"""

import typer
import logging
from typing import List, Optional, Dict, Any
import json

from .schemas import (
    BiasAuditResult,
    BiasFinding,
)
from .gemini_client import GeminiClient
from .utils import save_or_print_results, console
from .database import save_scan_to_db

logger = logging.getLogger(__name__)
gemini_client = GeminiClient()
bias_audit_app = typer.Typer()


def run_bias_audit(
    report_data: Dict[str, Any], report_identifier: str
) -> BiasAuditResult:
    """
    Uses an LLM to perform a meta-analysis on a JSON report to find bias.

    Args:
        report_data (Dict[str, Any]): The JSON data of the report to be audited.
        report_identifier (str): A name for the report (e.g., the filename).

    Returns:
        BiasAuditResult: A Pydantic model with the audit findings.
    """
    logger.info(f"Running bias audit on: {report_identifier}")

    try:
        serialized_report = json.dumps(report_data, indent=2, default=str)
    except Exception as e:
        logger.error(f"Could not serialize report for audit: {e}")
        return BiasAuditResult(
            report_identifier=report_identifier,
            error=f"Could not serialize report data: {e}",
        )

    # Truncate if too long to avoid excessive prompt size
    if len(serialized_report) > 10000:
        serialized_report = serialized_report[:10000] + "\n... [REPORT TRUNCATED] ..."

    prompt = f"""
You are a meta-analyst AI specializing in detecting cognitive and collection biases
in intelligence reports. Your job is to audit the provided JSON report.

Report to Audit:
{serialized_report}

Instructions:
Analyze the report and identify potential biases.
Return a JSON object with a single "findings" key.
"findings" should be a list of objects, each with:
- "bias_type" (str): The type of bias (e.g., "Confirmation Bias",
  "Collection Gap", "Over-reliance on Single Source", "Availability Heuristic").
- "evidence" (str): A quote or description from the report supporting this finding.
- "recommendation" (str): A suggestion to mitigate this bias.

Look for:
- **Confirmation Bias:** Does the analysis seem to only present data that
  supports one hypothesis? Are competing hypotheses ignored?
- **Collection Gaps:** Are there obvious missing pieces of information?
  (e.g., "No financial data", "No human intelligence").
- **Over-reliance on Single Source:** Does the data seem to come from only one
  module (e.g., "All data is from 'footprint'")?
- **Availability Heuristic:** Does the report overemphasize recent or
  sensational findings?
- **Loaded Language:** Is the language emotionally charged rather than objective?

Example "findings" list:
[
    {{
        "bias_type": "Over-reliance on Single Source",
        "evidence": "The 'analytical_summary' and 'hypotheses' appear to be based
                     entirely on the 'footprint' module's results.",
        "recommendation": "Cross-validate findings by running 'threat_intel' and
                          'social_analyzer' modules to gather different data types."
    }},
    {{
        "bias_type": "Collection Gap",
        "evidence": "The report contains no information about the target's leadership
                     or internal communications.",
        "recommendation": "Initiate collection for 'personnel_osint' or 'humint' to
                          fill this gap."
    }}
]
"""

    llm_response = gemini_client.generate_response(prompt)
    if not llm_response:
        error_msg = "LLM call for bias audit returned an empty response."
        logger.error(error_msg)
        return BiasAuditResult(report_identifier=report_identifier, error=error_msg)

    try:
        response_json = json.loads(llm_response)
        findings_data = response_json.get("findings", [])

        findings = [
            BiasFinding(
                bias_type=f.get("bias_type", "Unknown"),
                evidence=f.get("evidence", "N/A"),
                recommendation=f.get("recommendation", "N/A"),
            )
            for f in findings_data
        ]

        return BiasAuditResult(
            report_identifier=report_identifier,
            findings=findings,
            total_findings=len(findings),
        )
    except (json.JSONDecodeError, TypeError, AttributeError) as e:
        logger.error(f"Failed to parse LLM JSON response for bias audit: {e}")
        logger.debug(f"Raw LLM response: {llm_response}")
        return BiasAuditResult(
            report_identifier=report_identifier,
            error="Bias audit failed due to malformed LLM response.",
        )


@bias_audit_app.command("run")
def run_bias_audit_cli(
    input_file: str = typer.Argument(
        ...,
        help="Path to a JSON report file (e.g., output from another module) to be audited.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save audit results to a JSON file."
    ),
):
    """
    Audits a JSON analysis report for potential bias and data gaps.
    """
    try:
        with open(input_file, "r") as f:
            report_data = json.load(f)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/] Input file not found at '{input_file}'")
        raise typer.Exit(code=1)
    except json.JSONDecodeError:
        console.print(f"[bold red]Error:[/] Invalid JSON in file '{input_file}'")
        raise typer.Exit(code=1)

    with console.status(
        f"[bold cyan]Auditing report '{input_file}' for bias...[/bold cyan]"
    ):
        results_model = run_bias_audit(report_data, input_file)

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    # Note: Bias audit results are meta-analysis, not typically saved "against" a target
    # save_scan_to_db(target=input_file, module="bias_audit", data=results_dict)