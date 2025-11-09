"""
Module for Operational Security (OPSEC) Analysis.

Correlates data from multiple scans to find potential OPSEC weaknesses, such as
developers using compromised credentials, and assigns a quantifiable risk score.
Also includes proactive OPSEC footprint generation.
"""

import typer
import logging
import asyncio
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Set, Dict, Any
from typing_extensions import Annotated # Import Annotated

# --- Schema Imports ---
from .schemas import (
    OpsecReport, 
    CompromisedCommitter, 
    Organization,
    CodeIntelResult,
    SocialOSINTResult,
    FootprintResult
)
from .utils import save_or_print_results, calculate_risk_level
from .database import get_aggregated_data_for_target, save_scan_to_db
from .project_manager import resolve_target, get_project_assets

# --- Real Data-Gathering Imports ---
try:
    from .code_intel import search_repositories
    from .social_osint import search_profiles
    from .footprint import gather_footprint_data
except ImportError as e:
    logging.critical(f"OpsecAnalyzer failed to import core modules: {e}")
    # This will allow the 'run' command to work, but 'footprint' will fail.
    search_repositories = None
    search_profiles = None
    gather_footprint_data = None


logger = logging.getLogger(__name__)

# This is the app your plugin imports
opsec_app = typer.Typer()

# ---
# --- 1. OPSEC Risk Scoring ('run' command)
# ---

def generate_opsec_report(target: str) -> OpsecReport:
    """
    Generates an OPSEC report by correlating data from various modules
    and assigning a quantifiable risk score.
    """
    logger.info(f"Generating OPSEC report for {target}")
    aggregated_data = get_aggregated_data_for_target(target)
    if not aggregated_data:
        return OpsecReport(target=target, error="No historical data found for target.")
    
    modules = aggregated_data.get("modules", {})
    compromised_committers: List[CompromisedCommitter] = []
    
    # --- New Scoring Variables ---
    opsec_score = 100.0
    risk_factors: List[str] = []

    # --- Feature 1: Developer OPSEC Audit (Existing) ---
    committer_emails: Set[str] = set()
    code_intel_data = modules.get("code_intel_repo", {}).get("top_committers", [])
    for committer in code_intel_data:
        committer_emails.add(committer.get("email", "").lower())
    
    breach_data = modules.get("defensive_breaches", {}).get("breaches", [])
    if committer_emails and breach_data:
        breached_email_map: Dict[str, Set[str]] = {}
        for breach in breach_data:
            breach_name = breach.get("Name")
            if not breach_name:
                continue
            for email in breach.get("DataClasses", []):
                lower_email = email.lower()
                if "@" in lower_email:
                    if lower_email not in breached_email_map:
                        breached_email_map[lower_email] = set()
                    breached_email_map[lower_email].add(breach_name)
        
        for email in committer_emails:
            if email in breached_email_map:
                compromised_committers.append(
                    CompromisedCommitter(
                        email=email,
                        source_repository=modules.get("code_intel_repo", {}).get(
                            "repository_url"
                        ),
                        related_breaches=list(breached_email_map[email]),
                    )
                )

    # --- Feature 2: Quantifiable OPSEC Risk Scoring (NEW) ---
    
    # 1. Check for compromised developers (from logic above)
    if compromised_committers:
        num_compromised = len(compromised_committers)
        opsec_score -= num_compromised * 15 # -15 points per compromised dev
        risk_factors.append(f"{num_compromised} developer account(s) found in known data breaches.")

    # 2. Check for exposed secrets in code
    exposed_secrets = modules.get("code_intel_repo", {}).get("exposed_secrets", [])
    if exposed_secrets:
        num_secrets = len(exposed_secrets)
        opsec_score -= num_secrets * 10 # -10 points per exposed secret
        risk_factors.append(f"{num_secrets} exposed secret(s) (API keys, etc.) found in code.")

    # 3. Check for high-profile social media (larger attack surface)
    social_profiles = modules.get("social_osint", {}).get("profiles", [])
    if len(social_profiles) > 10:
        opsec_score -= 10
        risk_factors.append("Large social media footprint detected (high number of profiles).")

    # 4. Check for large external footprint
    subdomain_count = modules.get("footprint", {}).get("subdomains", {}).get("total", 0)
    if subdomain_count > 50:
        opsec_score -= 10 # -10 points for large attack surface
        risk_factors.append(f"Large external footprint ({subdomain_count} subdomains) increases attack surface.")

    # 5. Check for public-facing vulnerabilities
    vulns = modules.get("vulnerability_scanner", {}).get("scanned_hosts", [])
    if vulns:
        crit_vulns = sum(1 for h in vulns for p in h.get("open_ports", []) for v in p.get("vulnerabilities", []) if v.get("severity") == "critical")
        if crit_vulns > 0:
            opsec_score -= crit_vulns * 15 # -15 per critical vuln
            risk_factors.append(f"{crit_vulns} critical-severity vulnerability/vulnerabilities found on public hosts.")

    # Normalize score and determine level
    opsec_score = max(0.0, opsec_score) # Don't go below 0
    risk_level = calculate_risk_level(opsec_score, 100.0, is_score=True)

    return OpsecReport(
        target=target,
        compromised_committers=compromised_committers,
        opsec_score=opsec_score,
        risk_level=risk_level,
        risk_factors=risk_factors
    )


@opsec_app.command("run")
def run_opsec_analysis(
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="The target to analyze. Uses active project."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Correlates scan data to find operational security (OPSEC) weaknesses.
    """
    try:
        target_name = resolve_target(target, required_assets=["company_name", "domain"])
        results_model = generate_opsec_report(target_name)
        
        if not results_model.error:
            typer.echo(f"--- OPSEC Risk Report for {target_name} ---")
            score_color = typer.colors.GREEN
            if results_model.risk_level == "Medium":
                score_color = typer.colors.YELLOW
            elif results_model.risk_level in ["High", "Critical"]:
                score_color = typer.colors.RED
            
            typer.echo(f"Risk Score: {typer.style(f'{results_model.opsec_score:.1f}/100.0', fg=score_color, bold=True)}")
            typer.echo(f"Risk Level: {typer.style(results_model.risk_level, fg=score_color, bold=True)}")
            
            if results_model.risk_factors:
                typer.echo("\nKey Risk Factors:")
                for factor in results_model.risk_factors:
                    typer.echo(f"- {factor}")
            
            if results_model.compromised_committers:
                typer.echo("\nCompromised Developer Accounts:")
                for committer in results_model.compromised_committers:
                    typer.echo(f"- {committer.email} (Found in: {', '.join(committer.related_breaches)})")
            typer.echo("--------------------------------------")

        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file, print_to_console=False)
        save_scan_to_db(target=target_name, module="opsec_report", data=results_dict)
        
    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)


# ---
# --- 2. OPSEC Footprint ('footprint' command)
# ---

# --- Helper functions moved from opsec_footprint.py ---

async def _find_code_exposure(org_name: str) -> Dict[str, Any]:
    """
    Runs code_intel to find exposed secrets and committers.
    """
    if not search_repositories:
        return {"status": "error", "error": "CodeIntel module not imported."}
    try:
        result: CodeIntelResult = await search_repositories(org_name, limit=1)
        if not result or not result.repositories:
            return {"status": "no_repos_found", "secrets_found": 0, "top_committers": []}
        
        repo = result.repositories[0]
        return {
            "secrets_found": len(repo.exposed_secrets),
            "top_committers": [c.email for c in repo.top_committers[:5] if c.email],
            "source_repo": repo.url,
            "status": "completed"
        }
    except Exception as e:
        logger.error(f"Failed to find code exposure for {org_name}: {e}", exc_info=True)
        return {"error": str(e), "status": "error"}

async def _find_social_exposure(handles: List[str]) -> Dict[str, Any]:
    """
    Runs social_osint to find profile exposure.
    """
    if not search_profiles:
        return {"status": "error", "error": "SocialOSINT module not imported."}
    if not handles:
        return {"status": "no_handles_provided", "profiles_found": 0, "platforms": []}
    try:
        result: SocialOSINTResult = await search_profiles(handles)
        if not result or not result.profiles:
             return {"status": "no_profiles_found", "profiles_found": 0, "platforms": []}
             
        return {
            "profiles_found": len(result.profiles),
            "platforms": list(set(p.platform for p in result.profiles)),
            "status": "completed"
        }
    except Exception as e:
        logger.error(f"Failed to find social exposure for {handles}: {e}", exc_info=True)
        return {"error": str(e), "status": "error"}

async def _find_domain_exposure(domains: List[str]) -> Dict[str, Any]:
    """
    Runs footprint to find external attack surface.
    """
    if not gather_footprint_data:
        return {"status": "error", "error": "Footprint module not imported."}
    if not domains:
        return {"status": "no_domains_provided", "subdomain_count": 0, "open_ports": [], "technologies": []}
    try:
        primary_domain = domains[0]
        result: FootprintResult = await gather_footprint_data(primary_domain)
        if not result or not result.footprint:
             return {"status": "scan_failed", "subdomain_count": 0, "open_ports": [], "technologies": []}

        return {
            "subdomain_count": result.footprint.subdomains.get("total", 0),
            "open_ports": result.footprint.open_ports,
            "technologies": [t.get("name") for t in result.footprint.technologies if t.get("name")],
            "status": "completed"
        }
    except Exception as e:
        logger.error(f"Failed to find domain exposure for {domains}: {e}", exc_info=True)
        return {"error": str(e), "status": "error"}

async def _generate_footprint_report(organization: Organization, output_dir: Path) -> Dict[str, Any]:
    """
    Generates the full OPSEC footprint report by running all sub-modules.
    """
    logger.info(f"Generating OPSEC footprint for {organization.name}")
    report_data = {
        "organization": organization.name,
        "timestamp": datetime.now().isoformat(),
        "exposures": {},
    }

    # Run all exposure analyses concurrently
    tasks = {
        "code": _find_code_exposure(organization.name),
        "social": _find_social_exposure(organization.social_media_handles),
        "domain": _find_domain_exposure(organization.domains),
    }
    
    results = await asyncio.gather(*tasks.values())
    
    report_data["exposures"] = {
        "code": results[0],
        "social": results[1],
        "domain": results[2],
    }

    # Save report
    output_dir.mkdir(exist_ok=True)
    report_filename = f"opsec_footprint_{organization.name.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.json"
    report_path = output_dir / report_filename

    try:
        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
        logger.info(f"OPSEC Footprint report saved to {report_path}")
        report_data["report_path"] = str(report_path)
    except Exception as e:
        logger.error(f"Failed to save OPSEC report: {e}")
        report_data["report_path"] = None

    return report_data

# --- End helper functions ---


@opsec_app.command("footprint")
def run_opsec_footprint(
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="Target company name. Uses active project if None."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save report summary to JSON."
    ),
    report_dir: str = typer.Option(
        "reports", "--report-dir", help="Directory to save the full JSON report."
    ),
):
    """
    Generates a proactive Adversary Risk Exposure Report.
    """
    try:
        target_name = resolve_target(target, required_assets=["company_name", "domain"])
        
        # Fetch real organization details from the project
        domains = get_project_assets(target_name, 'domain')
        social_handles = get_project_assets(target_name, 'social')

        if not domains and not social_handles:
            typer.echo(f"[bold red]Error:[/bold red] No 'domain' or 'social' assets found for target '{target_name}'. Cannot generate footprint.", err=True)
            raise typer.Exit(code=1)
        
        org = Organization(
            name=target_name,
            domains=domains,
            social_media_handles=social_handles
        )
        
        typer.echo(f"Generating OPSEC Footprint for {org.name}...")
        
        # Run the async report generation
        output_path = Path(report_dir)
        report = asyncio.run(_generate_footprint_report(org, output_path))
        
        if report.get("report_path"):
            typer.echo(f"Report generation complete. Saved to: {report.get('report_path')}")
        else:
            typer.echo(f"[bold red]Error:[/bold red] Report generation failed. Check logs.", err=True)
        
        # Create a simple summary for database saving and optional JSON output
        summary = {
            "target": target_name,
            "report_path": report.get("report_path"),
            "code_secrets": report.get("exposures", {}).get("code", {}).get("secrets_found", 0),
            "social_profiles": report.get("exposures", {}).get("social", {}).get("profiles_found", 0),
            "subdomains": report.get("exposures", {}).get("domain", {}).get("subdomain_count", 0)
        }
        
        save_or_print_results(summary, output_file)
        save_scan_to_db(target=target_name, module="opsec_footprint_report", data=summary)

    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    opsec_app()