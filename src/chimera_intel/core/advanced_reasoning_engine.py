import logging
from typing import List
from .schemas import AnalysisResult, Hypothesis, Recommendation, ReasoningOutput

logger = logging.getLogger(__name__)


def decompose_objective(objective: str) -> List[str]:
    """
    Decomposes a complex objective into a series of simpler, actionable sub-objectives.
    This simulates an LLM's ability to break down tasks.
    """
    sub_objectives = []
    objective_lower = objective.lower()

    # If the objective is complex, break it down

    if "assess" in objective_lower and "propose measures" in objective_lower:
        sub_objectives.append(
            f"Assess the security posture of the target mentioned in '{objective}'"
        )
        sub_objectives.append(
            f"Propose mitigation measures based on the findings from '{objective}'"
        )
    else:
        # If simple, it's its own sub-objective

        sub_objectives.append(objective)
    return sub_objectives


def generate_reasoning(
    objective: str, results: List[AnalysisResult]
) -> ReasoningOutput:
    """
    The core function of the Reasoning Engine. It analyzes results, forms hypotheses,
    and proposes next steps and recommendations. This simulates LLM-driven reasoning.
    """
    summary_parts = []
    next_steps = []
    hypotheses = []
    recommendations = []
    known_ips = set()
    known_cves = set()
    critical_cves = []

    # Analyze the collected data to find new leads

    for result in results:
        # (The logic for generating next_steps remains the same as the previous reasoning_engine)

        if result.module_name == "footprint" and result.data:
            ips = getattr(result.data, "ip_addresses", [])
            summary_parts.append(
                f"Footprint analysis discovered {len(ips)} IP addresses."
            )
            for ip in ips:
                if ip not in known_ips:
                    next_steps.append(
                        {"module": "vulnerability_scanner", "params": {"ip": ip}}
                    )
                    known_ips.add(ip)
        elif result.module_name == "vulnerability_scanner" and result.data:
            vulns = result.data
            summary_parts.append(f"Vulnerability scan found {len(vulns)} CVEs.")
            for v in vulns:
                if v.cve not in known_cves:
                    next_steps.append(
                        {"module": "threat_intel", "params": {"indicator": v.cve}}
                    )
                    known_cves.add(v.cve)
        elif result.module_name == "threat_intel" and result.data:
            if getattr(result.data, "is_malicious", False):
                summary_parts.append(
                    f"Threat intelligence for {result.data.indicator} shows it is linked to malicious activity."
                )
                critical_cves.append(result.data.indicator)
    # Generate Hypotheses and Recommendations

    if critical_cves:
        hypotheses.append(
            Hypothesis(
                statement=f"The organization is likely targeted by threat actors exploiting {', '.join(critical_cves)}.",
                confidence=0.75,
            )
        )
        recommendations.append(
            Recommendation(
                action=f"Immediately patch systems vulnerable to {', '.join(critical_cves)} and monitor for signs of compromise.",
                priority="High",
            )
        )
    # Generate a final analytical summary

    if not summary_parts:
        analytical_summary = "Not enough data has been collected to form a conclusion."
    else:
        analytical_summary = " ".join(summary_parts)
        if "propose measures" in objective.lower() and recommendations:
            analytical_summary += " Based on the critical vulnerabilities found, immediate action is required."
        elif known_cves:
            analytical_summary += f" The primary attack surface appears to be related to the following CVEs: {', '.join(known_cves)}."
    return ReasoningOutput(
        analytical_summary=analytical_summary,
        hypotheses=hypotheses,
        recommendations=recommendations,
        next_steps=next_steps,
    )
