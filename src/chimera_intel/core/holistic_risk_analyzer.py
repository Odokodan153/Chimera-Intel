"""
Module for Holistic, Multi-Domain Risk Analysis.

Aggregates data from various intel modules (financial, legal, reputation)
to generate a comprehensive risk score for a target entity.
"""

import typer
import logging
from typing import List, Dict, Any, Optional
from .schemas import (
    HolisticRiskResult,
    RiskComponent)
from .utils import console, save_or_print_results
from .database import get_aggregated_data_for_target

# --- Import REAL schemas from existing modules ---
from .schemas import (
    SECFilingAnalysis, 
    LobbyingResult, 
    TradeDataResult, 
    HiringTrendsResult,
    EmployeeSentimentResult
)
from .reputation_model import ReputationModelResult
from .behavioral_analyzer import PsychographicProfileResult

logger = logging.getLogger(__name__)

def _calculate_financial_risk(modules: Dict[str, Any]) -> RiskComponent:
    """Calculates financial risk based on aggregated data."""
    score = 0.0
    justifications = []
    sources = []

    # Check for SEC filing risk factors (from corporate_intel module)
    sec_data = modules.get("corporate_sec_filings")
    if sec_data:
        sources.append("corporate_sec_filings")
        try:
            filing = SECFilingAnalysis.model_validate(sec_data)
            if filing.risk_factors_summary and "risk" in filing.risk_factors_summary.lower():
                score = max(score, 6.0) # SEC risks are significant
                justifications.append("Risk factors identified in 10-K filings.")
            if filing.error:
                score = max(score, 3.0) # Inability to parse is a minor risk
                justifications.append(f"Error processing SEC filings: {filing.error}")
        except Exception:
            pass # Ignore validation errors for old data

    if not justifications:
        justifications.append("No significant financial risk indicators found.")
        
    return RiskComponent(
        domain="Financial",
        score=score,
        justification=" ".join(justifications),
        source_modules=sources
    )

def _calculate_reputation_risk(modules: Dict[str, Any]) -> RiskComponent:
    """Calculates reputation risk based on aggregated data."""
    score = 0.0
    justifications = []
    sources = []
    
    # Check for reputation degradation models
    rep_model_data = modules.get("reputation_degradation_model") # Module name from reputation_model.py
    if rep_model_data:
        sources.append("reputation_degradation_model")
        try:
            rep_model = ReputationModelResult.model_validate(rep_model_data)
            if rep_model.projected_impact_score > 0:
                # Use the model's 0-10 score directly
                score = rep_model.projected_impact_score
                justifications.append(f"Active reputation attack model found with risk level '{rep_model.risk_level}'.")
        except Exception:
            pass

    # Check psychographic profile for narrative issues
    psych_data = modules.get("behavioral_psych_profile")
    if psych_data:
        sources.append("behavioral_psych_profile")
        try:
            psych = PsychographicProfileResult.model_validate(psych_data)
            if psych.narrative_entropy and psych.narrative_entropy.entropy_score > 2.5:
                score = max(score, 3.0) # High entropy can mean chaotic messaging
                justifications.append("Diverse/High-Entropy narrative detected, suggesting unfocused or chaotic public messaging.")
        except Exception:
            pass

    if not justifications:
        justifications.append("No active reputation threats or negative narrative signals detected.")

    return RiskComponent(
        domain="Reputation",
        score=score,
        justification=" ".join(justifications),
        source_modules=list(set(sources))
    )

def _calculate_legal_risk(modules: Dict[str, Any]) -> RiskComponent:
    """Calculates legal and regulatory risk."""
    score = 0.0
    justifications = []
    sources = []
    
    # Check for lobbying data (from corporate_intel module)
    lobby_data = modules.get("corporate_regulatory")
    if lobby_data:
        sources.append("corporate_regulatory")
        try:
            lobby_model = LobbyingResult.model_validate(lobby_data)
            if lobby_model.total_spent > 5000000: # Over $5M
                score = max(score, 6.0)
                justifications.append(f"Critical lobbying spend detected (${lobby_model.total_spent:,.0f}), indicating high regulatory dependency/risk.")
            elif lobby_model.total_spent > 1000000: # Over $1M
                score = max(score, 4.0)
                justifications.append(f"Significant lobbying spend detected (${lobby_model.total_spent:,.0f}).")
            elif lobby_model.total_spent > 0:
                score = max(score, 2.0)
                justifications.append("Active in regulatory lobbying.")
        except Exception:
            pass
            
    if not justifications:
        justifications.append("No significant legal or regulatory risk indicators found.")

    return RiskComponent(
        domain="Legal_Regulatory",
        score=score,
        justification=" ".join(justifications),
        source_modules=sources
    )

def _calculate_operational_risk(modules: Dict[str, Any]) -> RiskComponent:
    """Calculates operational risk (e.g., supply chain)."""
    score = 0.0
    justifications = []
    sources = []

    # Check supply chain data (from corporate_intel module)
    trade_data = modules.get("corporate_supplychain")
    if trade_data:
        sources.append("corporate_supplychain")
        try:
            trade = TradeDataResult.model_validate(trade_data)
            if trade.total_shipments == 0 and not trade.error:
                score = max(score, 3.0)
                justifications.append("No recent trade data found, indicating potential supply chain opacity or disruption.")
            elif trade.error:
                justifications.append("Could not assess trade data (API error).")
            else:
                justifications.append(f"Tracking {trade.total_shipments} shipments.")
        except Exception:
            pass

    if not justifications:
        justifications.append("No significant operational risk indicators found.")
        
    return RiskComponent(
        domain="Operational",
        score=score,
        justification=" ".join(justifications),
        source_modules=sources
    )

def _calculate_human_capital_risk(modules: Dict[str, Any]) -> RiskComponent:
    """Calculates risk from hiring and employee sentiment."""
    score = 0.0
    justifications = []
    sources = []

    # Check HR intel (from corporate_intel module)
    hr_data = modules.get("corporate_hr_intel")
    if hr_data:
        sources.append("corporate_hr_intel")
        try:
            # HR data is a dict containing sentiment and hiring
            sentiment = EmployeeSentimentResult.model_validate(hr_data.get("employee_sentiment", {}))
            hiring = HiringTrendsResult.model_validate(hr_data.get("hiring_trends", {}))

            if sentiment.overall_rating and sentiment.overall_rating < 3.0:
                score = max(score, 7.0)
                justifications.append(f"Critically low employee sentiment (Rating: {sentiment.overall_rating}/5.0).")
            elif sentiment.overall_rating and sentiment.overall_rating < 3.8:
                score = max(score, 4.0)
                justifications.append(f"Poor employee sentiment (Rating: {sentiment.overall_rating}/5.0).")

            if hiring.total_postings == 0 and not hiring.error:
                score = max(score, 2.0) # Minor risk
                justifications.append("Apparent hiring freeze (0 job postings detected).")

        except Exception:
            pass
            
    if not justifications:
        justifications.append("No significant human capital risk indicators found.")
        
    return RiskComponent(
        domain="Human_Capital",
        score=score,
        justification=" ".join(justifications),
        source_modules=sources
    )


def generate_holistic_risk_profile(target: str) -> HolisticRiskResult:
    """
    Generates a holistic risk profile by analyzing aggregated OSINT data.
    """
    logger.info(f"Generating holistic risk profile for {target}")
    aggregated_data = get_aggregated_data_for_target(target)

    if not aggregated_data:
        return HolisticRiskResult(
            target=target,
            overall_risk_score=0.0,
            risk_level="Low",
            risk_components=[],
            error="No historical data found for target."
        )

    modules = aggregated_data.get("modules", {})
    risk_components: List[RiskComponent] = []

    # 1. Calculate risk for each domain
    risk_components.append(_calculate_financial_risk(modules))
    risk_components.append(_calculate_reputation_risk(modules))
    risk_components.append(_calculate_legal_risk(modules))
    risk_components.append(_calculate_operational_risk(modules))
    risk_components.append(_calculate_human_capital_risk(modules))

    # 2. Calculate final weighted score
    if risk_components:
        total_score = sum(rc.score for rc in risk_components)
        overall_score = total_score / len(risk_components)
    else:
        overall_score = 0.0
        
    overall_score = round(overall_score, 2)

    if overall_score >= 7.0:
        risk_level = "Critical"
    elif overall_score >= 5.0:
        risk_level = "High"
    elif overall_score >= 3.0:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return HolisticRiskResult(
        target=target,
        overall_risk_score=overall_score,
        risk_level=risk_level,
        risk_components=risk_components
    )

# --- CLI Application ---

risk_app = typer.Typer(
    name="risk-analyzer",
    help="Generate holistic risk scores for targets."
)

@risk_app.command("run")
def run_holistic_analysis(
    target: str = typer.Argument(..., help="The target entity name to analyze."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Generates a holistic risk profile for a target by aggregating
    all known intelligence data from the database.
    """
    console.print(f"[bold cyan]Generating holistic risk profile for {target}...[/bold cyan]")
    
    with console.status("[spinner]Analyzing aggregated data..."):
        result = generate_holistic_risk_profile(target)

    if result.error:
        console.print(f"[bold red]Error during analysis:[/bold red] {result.error}")
        raise typer.Exit(code=1)

    console.print(f"\n[bold]Holistic Risk Profile for: {target}[/bold]")
    risk_color = "red"
    if result.risk_level == "Medium":
        risk_color = "yellow"
    elif result.risk_level == "Low":
        risk_color = "green"
        
    console.print(f"  Overall Score: [bold {risk_color}]{result.overall_risk_score:.2f} / 10.0[/bold {risk_color}]")
    console.print(f"  Risk Level: [bold {risk_color}]{result.risk_level}[/bold {risk_color}]\n")

    from rich.table import Table
    table = Table(title="Risk Component Breakdown")
    table.add_column("Domain", style="cyan")
    table.add_column("Score (0-10)", style="magenta")
    table.add_column("Justification")
    table.add_column("Source Modules", style="dim")

    for rc in result.risk_components:
        table.add_row(rc.domain, f"{rc.score:.2f}", rc.justification, ", ".join(rc.source_modules))
    
    console.print(table)
    
    if output_file:
        save_or_print_results(result.model_dump(), output_file, console)
        console.print(f"\n[green]Results saved to {output_file}[/green]")