import logging
import asyncio
from typing import Optional, List
from pydantic import BaseModel, Field
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from .threat_intel import get_threat_intel_otx, ThreatIntelResult
from .vulnerability_scanner import search_vulnerabilities, Vulnerability
from .threat_actor_intel import search_threat_actors, ThreatActor

logger = logging.getLogger(__name__)


class RiskAssessmentResult(BaseModel):
    """
    Represents the result of a risk assessment.
    """

    asset: str = Field(..., description="The asset at risk.")
    threat: str = Field(..., description="The threat to the asset.")
    probability: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="The probability of the threat occurring (0.0 to 1.0).",
    )
    impact: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="The impact of the threat if it occurs (0.0 to 10.0).",
    )
    risk_score: float = Field(
        ..., ge=0.0, le=10.0, description="The calculated risk score."
    )
    risk_level: str = Field(
        ..., description="The qualitative risk level (e.g., Low, Medium, High)."
    )
    details: Optional[ThreatIntelResult] = Field(
        None, description="Threat intelligence details."
    )
    vulnerabilities: List[Vulnerability] = Field(
        [], description="Vulnerabilities associated with the asset."
    )
    threat_actors: List[ThreatActor] = Field(
        [], description="Threat actors associated with the threat."
    )
    mitigation: List[str] = Field([], description="Suggested mitigation actions.")
    error: Optional[str] = Field(
        None, description="Any error that occurred during the assessment."
    )


def calculate_risk(
    asset: str,
    threat: str,
    probability: float,
    impact: float,
    details: Optional[ThreatIntelResult] = None,
    vulnerabilities: List[Vulnerability] = [],
    threat_actors: List[ThreatActor] = [],
) -> RiskAssessmentResult:
    """
    Calculates the risk score and level for a given asset and threat.
    """
    try:
        # Adjust impact based on vulnerabilities

        if vulnerabilities:
            impact = min(10.0, impact + len(vulnerabilities) * 0.5)
        # Adjust probability based on threat actor activity

        if threat_actors:
            probability = min(1.0, probability + len(threat_actors) * 0.1)
        risk_score = probability * impact

        if risk_score >= 7.0:
            risk_level = "Critical"
        elif risk_score >= 4.0:
            risk_level = "High"
        elif risk_score >= 2.0:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        # Generate mitigation suggestions

        mitigation = []
        if vulnerabilities:
            mitigation.append("Patch identified vulnerabilities.")
        if any(ta.name for ta in threat_actors):
            mitigation.append(
                "Monitor for TTPs associated with identified threat actors."
            )
        if risk_level in ["High", "Critical"]:
            mitigation.append(
                "Implement enhanced monitoring and incident response procedures."
            )
        return RiskAssessmentResult(
            asset=asset,
            threat=threat,
            probability=probability,
            impact=impact,
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            details=details,
            vulnerabilities=vulnerabilities,
            threat_actors=threat_actors,
            mitigation=mitigation,
        )
    except Exception as e:
        logger.error(
            "Error calculating risk for asset '%s' and threat '%s': %s",
            asset,
            threat,
            e,
        )
        return RiskAssessmentResult(
            asset=asset,
            threat=threat,
            probability=probability,
            impact=impact,
            risk_score=0.0,
            risk_level="Unknown",
            error=f"An error occurred during risk calculation: {e}",
        )


async def assess_risk_from_indicator(
    indicator: str, service: Optional[str] = None
) -> RiskAssessmentResult:
    """
    Assesses risk for an indicator by fetching threat intelligence,
    vulnerabilities, and threat actor information.
    """
    threat_intel_task = get_threat_intel_otx(indicator)
    vulnerabilities_task = (
        search_vulnerabilities(service) if service else asyncio.sleep(0, result=[])
    )
    threat_actors_task = search_threat_actors(indicator)

    threat_intel, vulnerabilities, threat_actors = await asyncio.gather(
        threat_intel_task, vulnerabilities_task, threat_actors_task
    )

    if not threat_intel or threat_intel.error:
        return RiskAssessmentResult(
            asset=indicator,
            threat="Unknown",
            probability=0.0,
            impact=0.0,
            risk_score=0.0,
            risk_level="Unknown",
            error=(
                threat_intel.error
                if threat_intel
                else "Could not fetch threat intelligence."
            ),
        )
    # Determine probability based on pulse count

    if threat_intel.pulse_count > 100:
        probability = 0.9
    elif threat_intel.pulse_count > 50:
        probability = 0.7
    elif threat_intel.pulse_count > 10:
        probability = 0.5
    elif threat_intel.pulse_count > 0:
        probability = 0.3
    else:
        probability = 0.1
    # Determine impact based on tags and malware families

    impact = 1.0
    high_impact_tags = ["ransomware", "apt", "malicious"]
    for pulse in threat_intel.pulses:
        for tag in pulse.tags:
            if tag.lower() in high_impact_tags:
                impact = max(impact, 9.0)
        for family in pulse.malware_families:
            if family:
                impact = max(impact, 8.0)
    threat = "Malicious Activity" if threat_intel.is_malicious else "Benign"

    return calculate_risk(
        asset=indicator,
        threat=threat,
        probability=probability,
        impact=impact,
        details=threat_intel,
        vulnerabilities=vulnerabilities,
        threat_actors=threat_actors,
    )


app = typer.Typer()


@app.command("assess-indicator")
def run_indicator_assessment(
    indicator: str = typer.Argument(..., help="The indicator (IP, domain) to assess."),
    service: str = typer.Option(
        None,
        "--service",
        "-s",
        help="The service running on the asset (e.g., 'apache').",
    ),
):
    """
    Assesses risk for an indicator using threat intelligence,
    vulnerability data, and threat actor information.
    """
    console = Console()

    async def assess():
        return await assess_risk_from_indicator(indicator, service)

    result = asyncio.run(assess())

    if result.error:
        console.print(f"[bold red]Error:[/] {result.error}")
        return
    table = Table(title=f"Risk Assessment for {indicator}")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Asset", result.asset)
    table.add_row("Threat", result.threat)
    table.add_row("Probability", str(result.probability))
    table.add_row("Impact", str(result.impact))
    table.add_row("Risk Score", str(result.risk_score))
    table.add_row(
        "Risk Level",
        f"[bold {'red' if result.risk_level in ['High', 'Critical'] else 'yellow' if result.risk_level == 'Medium' else 'green'}]{result.risk_level}[/]",
    )

    if result.details:
        table.add_row("OTX Pulses", str(result.details.pulse_count))
    console.print(table)

    if result.vulnerabilities:
        vuln_table = Table(title="Vulnerabilities")
        vuln_table.add_column("CVE", style="yellow")
        vuln_table.add_column("Severity", style="red")
        for v in result.vulnerabilities:
            vuln_table.add_row(v.cve, v.severity)
        console.print(vuln_table)
    if result.threat_actors:
        actor_table = Table(title="Associated Threat Actors")
        actor_table.add_column("Name", style="yellow")
        actor_table.add_column("TTPs", style="red")
        for a in result.threat_actors:
            actor_table.add_row(a.name, ", ".join(a.ttps))
        console.print(actor_table)
    if result.mitigation:
        mitigation_panel = Panel(
            "\n".join(f"- {m}" for m in result.mitigation),
            title="Mitigation Suggestions",
            border_style="green",
        )
        console.print(mitigation_panel)
