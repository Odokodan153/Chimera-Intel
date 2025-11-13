# src/chimera_intel/core/remediation_advisor.py

"""
Remediation Advisor Module.

This module provides actionable remediation plans for threats identified
by other Chimera Intel modules, such as the Vulnerability Scanner and
Counter-Intelligence modules. It answers the "how to patch" question.

Includes both structured (API/template) and AI-driven (Gemini) plans.
"""

import logging
import re
import asyncio
from typing import Optional, Dict, Any, List
import typer
# --- Internal Chimera Intel Imports ---
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.http_client import sync_client
from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.schemas import LegalTemplateResult
from chimera_intel.core.gemini_client import get_gemini_client # NEW: Added AI client
from .schemas import (
    RemediationPlanResult,
    RemediationStep,
)
# We can't import this directly without circular dependencies,
# so we'll call it as a separate module.
# For this implementation, we will import the specific function we need.
try:
    from chimera_intel.core.counter_intelligence import (
        get_legal_escalation_template
    )
    CAN_USE_LEGAL_TEMPLATES = True
except ImportError:
    CAN_USE_LEGAL_TEMPLATES = False
    pass 

# --- Remediation Functions ---

def get_remediation_for_cve(cve_id: str) -> RemediationPlanResult:
    """
    (Real) Fetches remediation details for a specific CVE from Vulners.

    This provides the "how to patch" for vulnerabilities found by the
    vulnerability_scanner.py module.
    """
    api_key = API_KEYS.vulners_api_key
    if not api_key:
        return RemediationPlanResult(
            threat_type="CVE",
            threat_identifier=cve_id,
            summary=f"Plan for {cve_id}",
            error="Vulners API key (VULNERS_API_KEY) is not configured."
        )

    logger.info(f"Querying Vulners for remediation plan for: {cve_id}")
    url = "https://vulners.com/api/v3/search/id"
    payload = {"apiKey": api_key, "id": cve_id}
    
    plan = RemediationPlanResult(
        threat_type="CVE",
        threat_identifier=cve_id,
        summary=f"Remediation Plan for {cve_id}",
    )

    try:
        response = sync_client.post(url, json=payload)
        response.raise_for_status()
        data = response.json()

        if not data.get("data", {}).get("documents"):
            plan.error = "CVE not found in Vulners or API error."
            return plan

        doc = data["data"]["documents"][cve_id]
        plan.summary = doc.get("title", f"Remediation Plan for {cve_id}")
        description = doc.get("description", "No description available.")
        
        steps = []
        
        # Priority 1: Understand the threat
        steps.append(RemediationStep(
            priority=1,
            description=f"Understand Vulnerability: {description[:300]}...",
            category="Investigate"
        ))

        # Priority 2: Find the patch
        patch_ref = None
        for ref in doc.get("references", []):
            ref_url = ref.get("refurl", "")
            ref_source = ref.get("refsource", "").lower()
            
            if ("advisory" in ref_source or 
                "patch" in ref_url.lower() or 
                "vendor" in ref_source):
                patch_ref = ref_url
                steps.append(RemediationStep(
                    priority=2,
                    description=f"Apply official patch from vendor. See advisory: {patch_ref}",
                    category="Patch",
                    reference=patch_ref
                ))
                break
        
        if not patch_ref:
            steps.append(RemediationStep(
                priority=2,
                description="No direct patch link found. Check primary vendor website for updates related to this CVE.",
                category="Patch"
            ))

        # Priority 3: Check for mitigations/workarounds
        if "workaround" in description.lower() or "mitigation" in description.lower():
            steps.append(RemediationStep(
                priority=3,
                description="A temporary mitigation or workaround may be available. Review the full vulnerability description and vendor advisory.",
                category="Mitigate"
            ))

        plan.steps = steps
        return plan

    except Exception as e:
        logger.error(f"Error querying Vulners for CVE {cve_id}: {e}")
        plan.error = f"An API error occurred: {e}"
        return plan


def get_remediation_for_hostile_infra(
    indicator: str,
    details: Dict[str, Any]
) -> RemediationPlanResult:
    """
    (Real) Generates a remediation plan for hostile infrastructure.

    This provides the "how to patch" for threats found by the
    counter_intelligence.py `search_collection_infrastructure` function.
    """
    steps = [
        RemediationStep(
            priority=1,
            description=f"Add indicator {indicator} to all firewall, proxy, and EDR blocklists immediately.",
            category="Block"
        ),
        RemediationStep(
            priority=2,
            description=f"Monitor internal network (e.g., DNS, NetFlow) logs for any past or present communication with {indicator}.",
            category="Monitor"
        ),
        RemediationStep(
            priority=3,
            description=f"Investigate the service banner: {details.get('banner', 'N/A')}. Ensure this service is not an exposed internal asset.",
            category="Investigate",
            reference=f"Port: {details.get('port')}, ASN: {details.get('asn')}"
        ),
        RemediationStep(
            priority=4,
            description="If communication is found, assume breach and initiate incident response procedures for affected assets.",
            category="Response"
        )
    ]
    return RemediationPlanResult(
        threat_type="Hostile Infrastructure",
        threat_identifier=indicator,
        summary=f"Action plan for potential hostile C2 or scanner: {indicator}",
        steps=steps
    )


def get_remediation_for_lookalike_domain(
    domain: str,
    brand_name: str
) -> RemediationPlanResult:
    """
    (Real) Generates a remediation plan for a lookalike domain.

    This provides the "how to patch" for threats found by the
    counter_intelligence.py `monitor_impersonation` function.
    It reuses the `get_legal_escalation_template` function.
    """
    steps = [
        RemediationStep(
            priority=1,
            description=f"Do NOT visit the malicious domain: {domain}. Warn all employees via internal communication.",
            category="Mitigate"
        ),
        RemediationStep(
            priority=2,
            description=f"Contact the domain registrar for {domain} to report abuse, impersonation, and phishing.",
            category="Legal"
        ),
        RemediationStep(
            priority=3,
            description="Monitor the domain for any changes, such as MX record setup (indicating phishing email) or content copying.",
            category="Monitor"
        )
    ]

    # Reuse logic from counter_intelligence module
    if CAN_USE_LEGAL_TEMPLATES:
        template_result: LegalTemplateResult = get_legal_escalation_template(
            "impersonation-report"
        )
        if template_result.template_body:
            steps.append(RemediationStep(
                priority=2,
                description="Use the 'impersonation-report' template to submit a formal takedown request.",
                category="Legal",
                reference=f"Contacts: {template_result.contacts}"
            ))
        else:
            steps.append(RemediationStep(
                priority=2,
                description="Begin legal takedown process. Use 'legal-template --help' to find available templates.",
                category="Legal"
            ))

    return RemediationPlanResult(
        threat_type="Domain Impersonation",
        threat_identifier=domain,
        summary=f"Action plan for lookalike domain targeting '{brand_name}'",
        steps=steps
    )


def get_remediation_for_insider_threat(
    personnel_id: str,
    key_factors: List[str]
) -> RemediationPlanResult:
    """
    (Real) Generates a remediation plan for a high-risk insider.

    This provides the "how to patch" for threats found by the
    counter_intelligence.py `score_insider_threat` function.
    """
    steps = [
        RemediationStep(
            priority=1,
            description=f"Discreetly escalate findings for {personnel_id} to the Security and Human Resources departments.",
            category="Legal"
        ),
        RemediationStep(
            priority=2,
            description=f"Initiate a review of {personnel_id}'s access rights and recent activity logs, especially regarding: {', '.join(key_factors)}",
            category="Monitor"
        ),
        RemediationStep(
            priority=3,
            description="If local file leaks were found, secure the workstation and perform forensic analysis.",
            category="Investigate"
        ),
        RemediationStep(
            priority=4,
            description="Review data egress policies and endpoint protection (DLP) to prevent future leaks.",
            category="Mitigate"
        )
    ]
    return RemediationPlanResult(
        threat_type="Insider Threat Risk",
        threat_identifier=personnel_id,
        summary=f"Action plan for high-risk personnel: {personnel_id}",
        steps=steps
    )

# --- NEW: AI-Driven Remediation ---

def _parse_ai_remediation(text: str) -> List[RemediationStep]:
    """Parses a numbered list from AI into RemediationStep objects."""
    steps = []
    # Regex to find lines starting with a number, period, and space
    # e.g., "1. Do this."
    # We also capture the category if it's in brackets, e.g., "1. Do this [Patch]"
    step_pattern = re.compile(
        r"^\s*(\d+)\.\s*(.*?)(?:\s*\[(Patch|Block|Monitor|Legal|Investigate|Mitigate|Response)\])?\s*$",
        re.MULTILINE | re.IGNORECASE
    )
    
    matches = step_pattern.findall(text)
    
    if matches:
        for match in matches:
            try:
                priority = int(match[0])
                description = match[1].strip()
                # Default category if not found
                category = match[2].strip().capitalize() if match[2] else "Investigate"
                
                steps.append(RemediationStep(
                    priority=priority,
                    description=description,
                    category=category
                ))
            except Exception as e:
                logger.warning(f"Failed to parse AI step: {match} - {e}")
    
    # Fallback if regex fails: just split by line
    if not steps and text:
        lines = text.split('\n')
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            # Remove potential numbering
            line = re.sub(r"^\s*\d+\.\s*", "", line)
            steps.append(RemediationStep(
                priority=i,
                description=line,
                category="Investigate"
            ))
            
    return steps

async def get_remediation_with_ai(
    threat_type: str, 
    threat_details: str
) -> RemediationPlanResult:
    """
    (Real) Generates a remediation plan using the Gemini AI client.
    
    This is the fallback "just in case" AI to provide remediation for
    any threat type that doesn't have a structured plan.
    """
    plan = RemediationPlanResult(
        threat_type=threat_type,
        threat_identifier=threat_details[:75], # Truncate long details
        summary=f"AI-Generated Remediation Plan for {threat_type}"
    )
    
    try:
        client = get_gemini_client()
        if not client:
            plan.error = "Gemini AI client is not configured."
            return plan

        logger.info(f"Querying Gemini for remediation for: {threat_type}")
        
        prompt = f"""
        You are a senior cybersecurity remediation expert.
        A threat has been detected. Generate a concise, actionable, 
        step-by-step remediation plan.
        
        Threat Type: {threat_type}
        Threat Details: {threat_details}
        
        Format your response as a numbered list.
        For each step, provide a category in brackets, e.g.:
        1. Do this first. [Block]
        2. Do this second. [Patch]
        3. Do this third. [Monitor]
        
        Available categories: [Patch, Block, Monitor, Legal, Investigate, Mitigate, Response]
        """
        
        ai_response = await client.generate_text_response(prompt)
        
        if not ai_response:
            plan.error = "AI returned an empty response."
            return plan
        
        plan.steps = _parse_ai_remediation(ai_response)
        
        if not plan.steps:
             plan.error = "AI responded, but steps could not be parsed."
        
        return plan

    except Exception as e:
        logger.error(f"Error querying Gemini for remediation: {e}")
        plan.error = f"An AI API error occurred: {e}"
        return plan


# --- Typer CLI Application ---

remediation_app = typer.Typer()
logger = logging.getLogger(__name__)

@remediation_app.command("cve")
def run_get_cve_remediation(
    cve_id: str = typer.Argument(
        ...,
        help="The CVE ID to get a patch/remediation plan for (e.g., 'CVE-2021-44228')."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """(Real) Gets a 'how-to-patch' plan for a specific CVE."""
    with console.status(
        f"[bold cyan]Generating remediation plan for {cve_id}...[/bold cyan]"
    ):
        results = get_remediation_for_cve(cve_id)
    
    results_dict = results.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=cve_id, module="remediation_cve", data=results_dict
    )

@remediation_app.command("domain")
def run_get_domain_remediation(
    domain: str = typer.Argument(
        ...,
        help="The lookalike domain found (e.g., 'chimera-intol.com')."
    ),
    brand_name: str = typer.Argument(
        ...,
        help="The official brand name being impersonated (e.g., 'Chimera Intel')."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    (Real) Gets a 'how-to-patch' plan for a lookalike domain.
    
    This is the remediation for a counter-intelligence 'domain-watch' finding.
    """
    with console.status(
        f"[bold cyan]Generating remediation plan for {domain}...[/bold cyan]"
    ):
        results = get_remediation_for_lookalike_domain(domain, brand_name)
    
    results_dict = results.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=domain, module="remediation_domain", data=results_dict
    )

@remediation_app.command("infra")
def run_get_infra_remediation(
    indicator: str = typer.Argument(
        ...,
        help="The hostile IP or domain (e.g., '1.2.3.4')."
    ),
    port: int = typer.Option(
        0, help="Port number associated with the finding."
    ),
    banner: str = typer.Option(
        "", help="Service banner from Shodan."
    ),
    asn: str = typer.Option(
        "", help="ASN of the indicator."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    (Real) Gets a 'how-to-patch' plan for hostile infrastructure.

    This is the remediation for a counter-intelligence 'infra-check' finding.
    """
    details = {"port": port, "banner": banner, "asn": asn}
    with console.status(
        f"[bold cyan]Generating remediation plan for {indicator}...[/bold cyan]"
    ):
        results = get_remediation_for_hostile_infra(indicator, details)
    
    results_dict = results.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=indicator, module="remediation_infra", data=results_dict
    )

@remediation_app.command("ai-plan")
def run_get_ai_remediation(
    threat_type: str = typer.Argument(
        ...,
        help="The type of threat (e.g., 'Phishing Email', 'Data Leak')."
    ),
    threat_details: str = typer.Argument(
        ...,
        help="A brief description of the threat (e.g., 'User reported email from fake-ceo.com')."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """(Real) Generates a 'how-to-patch' plan using AI for any threat."""
    
    with console.status(
        f"[bold cyan]Asking AI for remediation plan for '{threat_type}'...[/bold cyan]"
    ):
        # We run the async function from our sync Typer command
        try:
            results = asyncio.run(get_remediation_with_ai(threat_type, threat_details))
        except Exception as e:
            results = RemediationPlanResult(
                threat_type=threat_type,
                threat_identifier=threat_details,
                summary="Failed to run async AI plan",
                error=str(e)
            )

    results_dict = results.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=threat_type, module="remediation_ai", data=results_dict
    )


if __name__ == "__main__":
    remediation_app()