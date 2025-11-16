"""
Chimera-Intel Advanced Purple Team Engine
-----------------------------------------

This module orchestrates Red, Defensive, CTI, Risk, and Simulation
modules to run advanced, multi-stage purple team exercises.

It moves beyond simple correlation to provide:
1.  Full "Kitchen Sink" analysis.
2.  Hypothesis-driven TTP hunting.
3.  CTI-driven threat actor emulation.
"""

import logging
import typer
import json
from typing import Dict, Any, Optional, List
from . import red_team
from . import defensive
from . import ai_core
from . import threat_actor_intel  
from . import ttp_mapper           
from . import risk_assessment      
from . import attack_path_simulator 
from .database import save_scan_to_db   
from .config_loader import API_KEYS
from .utils import console

# Configure logger
logger = logging.getLogger(__name__)

# Create the Typer app for purple team commands
purple_team_app = typer.Typer(
    name="purple-team",
    help="Run advanced, multi-stage Red/Blue/CTI exercises.",
    no_args_is_help=True
)


# --- ORCHESTRATION PHASES ---

def run_red_team_phase(target: str) -> Dict[str, Any]:
    """Phase 1: Generates AI-driven attack vectors."""
    console.print(f"\n[bold magenta]Phase 1: Running Red Team Analysis for {target}...[/bold magenta]")
    try:
        red_report = red_team.generate_attack_vectors(target)
        if not red_report:
            return {"status": "No aggregated data found for target."}
        return red_report
    except Exception as e:
        logger.error(f"Red Team analysis failed for {target}: {e}", exc_info=True)
        return {"error": f"Red Team analysis failed: {e}"}


def run_defensive_phase(
    target: str,
    scan_dir: Optional[str],
    apk_path: Optional[str],
    github_query: str,
    pastes_query: str,
    skip_slow_scans: bool
) -> Dict[str, Any]:
    """Phase 2: Runs a comprehensive battery of defensive scanners."""
    console.print(f"\n[bold blue]Phase 2: Running Defensive Footprint Scan for {target}...[/bold blue]")
    
    defensive_results: Dict[str, Any] = {}
    keys = API_KEYS
    
    try:
        # --- Domain/Query-Based Scans ---
        if keys.hibp_api_key:
            console.print("[cyan]  Checking for breaches (HIBP)...[/cyan]")
            defensive_results["breaches"] = defensive.check_hibp_breaches(target, keys.hibp_api_key).model_dump()
        
        if keys.github_pat:
            console.print(f"[cyan]  Checking for GitHub leaks (Query: {github_query})...[/cyan]")
            defensive_results["github_leaks"] = defensive.search_github_leaks(github_query, keys.github_pat).model_dump()

        console.print("[cyan]  Checking for public pastes...[/cyan]")
        defensive_results["public_pastes"] = defensive.search_pastes_api(pastes_query).model_dump()

        console.print("[cyan]  Checking for typosquatting (dnstwist)...[/cyan]")
        defensive_results["typosquatting"] = defensive.find_typosquatting_dnstwist(target).model_dump()

        if keys.shodan_api_key:
            shodan_query = f"domain:\"{target}\""
            console.print(f"[cyan]  Checking attack surface (Shodan: {shodan_query})...[/cyan]")
            defensive_results["attack_surface"] = defensive.analyze_attack_surface_shodan(shodan_query, keys.shodan_api_key).model_dump()

        console.print("[cyan]  Checking Certificate Transparency logs...[/cyan]")
        defensive_results["certificate_logs"] = defensive.monitor_ct_logs(target).model_dump()

        console.print("[cyan]  Checking web headers (Mozilla Observatory)...[/cyan]")
        moz_res = defensive.analyze_mozilla_observatory(target)
        defensive_results["web_headers"] = moz_res.model_dump() if moz_res else {"status": "Scan failed or timed out"}

        if not skip_slow_scans:
            console.print("[cyan]  Running SSL Labs analysis... (this is slow)[/cyan]")
            defensive_results["ssl_configuration"] = defensive.analyze_ssl_ssllabs(target).model_dump()
        else:
            defensive_results["ssl_configuration"] = {"status": "Skipped"}

        # --- Path-Based Scans (Conditional) ---
        if scan_dir:
            console.print(f"[cyan]  Scanning local directory for IaC issues: {scan_dir}[/cyan]")
            defensive_results["iac_scan"] = defensive.scan_iac_files(scan_dir).model_dump()

            console.print(f"[cyan]  Scanning local directory for secrets: {scan_dir}[/cyan]")
            defensive_results["secrets_scan"] = defensive.scan_for_secrets(scan_dir).model_dump()
        
        if apk_path and keys.mobsf_api_key:
            mobsf_url = "http://127.0.0.1:8000" # Or from config
            console.print(f"[cyan]  Scanning APK file with MobSF: {apk_path}[/cyan]")
            defensive_results["mobsf_scan"] = defensive.analyze_apk_mobsf(apk_path, mobsf_url, keys.mobsf_api_key).model_dump()
        elif apk_path:
            defensive_results["mobsf_scan"] = {"status": "Skipped (MOBSF_API_KEY not set)"}

    except Exception as e:
        logger.error(f"Defensive analysis failed for {target}: {e}", exc_info=True)
        defensive_results["error"] = f"Defensive analysis phase failed: {e}"
    
    return defensive_results


def run_threat_intel_phase(target_industry: str) -> Dict[str, Any]:
    """Phase 3: Gathers CTI on relevant threat actors and their TTPs."""
    console.print("\n[bold red]Phase 3: Gathering Cyber Threat Intelligence...[/bold red]")
    if not target_industry:
        return {"status": "Skipped (No industry specified)"}
    
    try:
        # NOTE: Assuming function names for these modules
        console.print(f"[cyan]  Finding threat actors targeting industry: {target_industry}[/cyan]")
        actors = threat_actor_intel.get_actors_by_industry(target_industry)
        if not actors:
            return {"status": "No relevant threat actors found."}

        actor_ttp_map = {}
        for actor in actors:
            actor_name = actor.get("name", "Unknown")
            console.print(f"[cyan]    Mapping TTPs for actor: {actor_name}[/cyan]")
            ttps = ttp_mapper.get_ttps_for_actor(actor_name)
            actor_ttp_map[actor_name] = ttps

        return {
            "relevant_actors": actors,
            "actor_ttp_map": actor_ttp_map
        }
    except Exception as e:
        logger.error(f"Threat Intel phase failed: {e}", exc_info=True)
        return {"error": f"Threat Intel phase failed: {e}"}


def run_correlation_phase(
    red_report: Dict[str, Any], 
    defensive_report: Dict[str, Any], 
    threat_intel_report: Dict[str, Any]
) -> Dict[str, Any]:
    """Phase 4: Uses AI to correlate all three reports for gap analysis."""
    console.print("\n[bold yellow]Phase 4: Running AI Correlation and Gap Analysis...[/bold yellow]")
    
    api_key = API_KEYS.google_api_key
    if not api_key:
        console.print("[bold red]Error:[/bold red] Google API key not configured. Cannot run correlation.")
        return {"error": "Google API key not found."}

    red_text = json.dumps(red_report, indent=2, default=str)
    def_text = json.dumps(defensive_report, indent=2, default=str)
    cti_text = json.dumps(threat_intel_report, indent=2, default=str)

    prompt = f"""
    You are a world-class Purple Team lead and CTI analyst. Your job is to perform an 
    in-depth gap analysis by correlating three sources of information:
    1.  **Red Team Report (Potential Attacks):** An AI-generated plan of plausible attack vectors.
    2.  **Defensive Footprint (Actual Posture):** A real-time scan of the target's external defenses.
    3.  **Threat Intel Report (Relevant Actors):** A CTI brief on known threat actors and their TTPs.

    **Red Team Report:**
    ```json
    {red_text}
    ```

    **Defensive Footprint:**
    ```json
    {def_text}
    ```

    **Threat Intel Report:**
    ```json
    {cti_text}
    ```

    **Your Task (Generate 3 Sections):**

    **Section 1: Triaged Gap Analysis**
    Analyze all three reports and identify security gaps, triaging them into three levels of urgency.
    
    * **Critical Gaps (Highest Priority):**
        List all findings where a Red Team TTP, a real Threat Actor TTP, *and* a
        Defensive weakness *all align*. These are the most critical, confirmed risks.
        (e.g., "Red: T1566 Phishing, CTI: APT29 uses T1566, Blue: 'typosquatting' scan found 5 unregistered domains.")

    * **Threat-Informed Gaps (High Priority):**
        List findings where a real Threat Actor TTP and a Defensive weakness align,
        *even if* it wasn't in the Red Team report. These are risks from known adversaries.
        (e.g., "CTI: FIN7 uses T1213, Blue: 'github_leaks' found 2 potential API keys.")

    * **Postural Gaps (Medium Priority):**
        List findings where a Red Team TTP and a Defensive weakness align, but there
        is no specific CTI data to support it. These are general best-practice failures.
        (e.g., "Red: T1190 Exploit Public App, Blue: 'web_headers' scan shows an 'F' grade and missing HSTS.")

    **Section 2: Identified Strengths**
    Explicitly point out where controls are strong.
    (e.g., "Red Team suggested T1003, but 'secrets_scan' found 0 hardcoded credentials.")

    **Section 3: Prioritized Recommendations**
    Provide a numbered list of the top 5 *actionable* recommendations, starting with the
    most critical. Each recommendation must be justified by your gap analysis.
    
    Provide your response in clear, professional markdown.
    """

    try:
        ai_result = ai_core.generate_swot_from_data(prompt, api_key)
        if ai_result.error:
            logger.error(f"AI Correlation Error: {ai_result.error}")
            return {"error": f"AI analysis failed: {ai_result.error}"}
        
        # We also need to *programmatically* extract the gaps for Phase 5
        # This would ideally involve a more structured AI output, but for now, we pass the text.
        return {
            "analysis_text": ai_result.analysis_text,
            "programmatic_gaps": [
                # In a real-world extension, an NLP function would parse
                # the 'Critical Gaps' from 'analysis_text'
                # For now, we pass a placeholder.
                {"gap_id": "G-001", "description": "Example Gap: Phishing Risk", "ttp": "T1566"}
            ] 
        }
        
    except Exception as e:
        logger.error(f"AI Correlation phase failed: {e}", exc_info=True)
        return {"error": f"AI correlation failed: {e}"}


def run_risk_simulation_phase(
    target: str,
    gaps: List[Dict[str, Any]],
    defensive_report: Dict[str, Any]
) -> Dict[str, Any]:
    """Phase 5: Scores risk for identified gaps and simulates attack paths."""
    console.print("\n[bold cyan]Phase 5: Running Risk Assessment & Attack Simulation...[/bold cyan]")
    
    risk_report = {}
    sim_report = {}

    try:
        # 1. Risk Assessment
        # NOTE: Assuming function `calculate_risk_for_gap` exists in `risk_assessment`
        console.print("[cyan]  Scoring risk for critical gaps...[/cyan]")
        scored_gaps = []
        for gap in gaps:
            # Pass gap info and relevant blue data to risk module
            relevant_blue_findings = defensive_report.get("typosquatting") # Example
            score_result = risk_assessment.calculate_risk_for_gap(gap, relevant_blue_findings)
            scored_gaps.append(score_result)
        
        risk_report = {"scored_gaps": scored_gaps}

    except Exception as e:
        logger.error(f"Risk Assessment phase failed: {e}", exc_info=True)
        risk_report = {"error": f"Risk Assessment phase failed: {e}"}

    try:
        # 2. Attack Path Simulation
        # NOTE: Assuming function `generate_simulated_paths` exists
        console.print("[cyan]  Generating simulated attack paths...[/cyan]")
        confirmed_vulns = [g for g in risk_report.get("scored_gaps", []) if g.get("rating") in ("Critical", "High")]
        if confirmed_vulns:
            sim_paths = attack_path_simulator.generate_simulated_paths(target, confirmed_vulns)
            sim_report = {"paths": sim_paths}
        else:
            sim_report = {"status": "No high-risk, confirmed vulnerabilities to simulate."}
            
    except Exception as e:
        logger.error(f"Attack Simulation phase failed: {e}", exc_info=True)
        sim_report = {"error": f"Attack Simulation phase failed: {e}"}

    return {
        "risk_assessment_report": risk_report,
        "attack_simulation_report": sim_report
    }


# --- CLI COMMANDS ---

@purple_team_app.command("run-exercise")
def run_exercise_cli(
    target: str = typer.Argument(
        ..., 
        help="The target domain for the exercise (e.g., example.com)."
    ),
    industry: str = typer.Option(
        None,
        help="Target's industry (e.g., 'Financial Services') for CTI."
    ),
    scan_dir: Optional[str] = typer.Option(
        None,
        "--scan-dir",
        help="Path to a local directory for IaC and secrets scanning."
    ),
    apk_path: Optional[str] = typer.Option(
        None,
        "--apk-path",
        help="Path to a local .apk file for MobSF scanning."
    ),
    github_query: Optional[str] = typer.Option(
        None,
        help="Custom GitHub query. Defaults to the target domain."
    ),
    pastes_query: Optional[str] = typer.Option(
        None,
        help="Custom pastes query. Defaults to the target domain."
    ),
    skip_slow_scans: bool = typer.Option(
        False,
        "--skip-slow",
        help="Skip very slow scans like SSL Labs."
    )
):
    """
    Run a full, 5-phase purple team exercise.
    
    Orchestrates: Red Team, Defensive, CTI, AI Correlation, and Risk/Simulation.
    """
    console.print(f"[bold green]Starting Full 5-Phase Purple Team Exercise for: {target}[/bold green]")
    
    gh_query = github_query or target
    p_query = pastes_query or target

    final_report: Dict[str, Any] = {
        "exercise_type": "full_5_phase",
        "target": target,
        "parameters": {
            "industry": industry,
            "scan_dir": scan_dir,
            "apk_path": apk_path,
            "github_query": gh_query,
            "pastes_query": p_query,
            "skip_slow_scans": skip_slow_scans
        },
        "phase_1_red_team": None,
        "phase_2_defensive": None,
        "phase_3_threat_intel": None,
        "phase_4_ai_correlation": None,
        "phase_5_risk_simulation": None
    }

    try:
        # Run all 5 phases
        final_report["phase_1_red_team"] = run_red_team_phase(target)
        final_report["phase_2_defensive"] = run_defensive_phase(
            target, scan_dir, apk_path, gh_query, p_query, skip_slow_scans
        )
        final_report["phase_3_threat_intel"] = run_threat_intel_phase(industry)
        
        correlation_report = run_correlation_phase(
            final_report["phase_1_red_team"],
            final_report["phase_2_defensive"],
            final_report["phase_3_threat_intel"]
        )
        final_report["phase_4_ai_correlation"] = correlation_report

        gaps = correlation_report.get("programmatic_gaps", [])
        final_report["phase_5_risk_simulation"] = run_risk_simulation_phase(
            target, gaps, final_report["phase_2_defensive"]
        )

        # --- Final Report ---
        report_json = json.dumps(final_report, indent=4, default=str)
        console.secho(f"\n--- Purple Team Exercise Complete ---", fg=typer.colors.GREEN, bold=True)
        typer.echo(report_json)

        # Save to DB
        console.print(f"\n[bold]Saving exercise results to database...[/bold]")
        save_scan_to_db(
            target=target, 
            module="purple_team_exercise", 
            data=final_report
        )
        console.print("[green]Successfully saved to database.[/green]")

    except Exception as e:
        logger.error(f"Failed to execute full exercise: {e}", exc_info=True)
        console.secho(f"Error: Failed to run exercise: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)


@purple_team_app.command("hunt-ttp")
def hunt_ttp_cli(
    ttp_id: str = typer.Argument(
        ..., 
        help="The MITRE ATT&CK TTP ID to hunt for (e.g., T1566)."
    ),
    target: str = typer.Argument(
        ..., 
        help="The target domain to test this TTP against."
    )
):
    """
    Test defenses against a *specific* TTP (Hypothesis-Driven).
    """
    console.print(f"[bold green]Starting TTP Hunt for {ttp_id} against {target}[/bold green]")
    report = {
        "exercise_type": "ttp_hunt",
        "ttp_id": ttp_id,
        "target": target,
        "ttp_details": None,
        "relevant_defensive_findings": {},
        "ai_assessment": None
    }
    
    try:
        # 1. Get TTP Details
        # NOTE: Assuming function name
        report["ttp_details"] = ttp_mapper.get_ttp_details(ttp_id)
        if not report["ttp_details"]:
            console.secho(f"Could not find details for TTP: {ttp_id}", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        # 2. Run *Targeted* Defensive Scans
        # This logic would be complex, mapping TTPs to specific defensive functions
        console.print(f"[cyan]Running defensive checks relevant to {ttp_id}...[/cyan]")
        if ttp_id in ("T1566", "T1566.001", "T1566.002"): # Phishing
            report["relevant_defensive_findings"]["typosquatting"] = defensive.find_typosquatting_dnstwist(target).model_dump()
            if API_KEYS.hibp_api_key:
                report["relevant_defensive_findings"]["breaches"] = defensive.check_hibp_breaches(target, API_KEYS.hibp_api_key).model_dump()
        elif ttp_id in ("T1190", "T1133"): # Exploit Public App / External Services
             if API_KEYS.shodan_api_key:
                report["relevant_defensive_findings"]["attack_surface"] = defensive.analyze_attack_surface_shodan(f"domain:\"{target}\"", API_KEYS.shodan_api_key).model_dump()
        # ... more mappings would be added here ...
        else:
            console.print(f"[yellow]No specific defensive mapping for {ttp_id} yet. Add one.[/yellow]")


        # 3. Call AI for Assessment
        console.print(f"[cyan]Requesting AI assessment for {ttp_id}...[/cyan]")
        prompt = f"""
        You are a Purple Team specialist. Your task is to assess the defensive posture 
        for a specific MITRE TTP.

        **TTP Under Review:**
        {json.dumps(report["ttp_details"], indent=2)}

        **Defensive Findings (Blue Team):**
        {json.dumps(report["relevant_defensive_findings"], indent=2, default=str)}

        **Task:**
        Based *only* on the defensive findings, assess the organization's preparedness
        against this TTP. Rate the defense as 'High', 'Medium', 'Low', or 'None' and
        provide a 1-2 sentence justification.

        **Example Assessment:**
        "Defense Rating: Low
        Justification: The TTP involves phishing, and the 'typosquatting' scan
        revealed 12 unregistered, high-risk domains, providing a clear path
        for an attacker to execute this technique."
        """
        
        api_key = API_KEYS.google_api_key
        if api_key:
            ai_result = ai_core.generate_swot_from_data(prompt, api_key)
            report["ai_assessment"] = ai_result.analysis_text or ai_result.error
        else:
            report["ai_assessment"] = "Error: Google API key not found."

        typer.echo(json.dumps(report, indent=4, default=str))

    except Exception as e:
        logger.error(f"Failed to execute TTP hunt: {e}", exc_info=True)
        console.secho(f"Error: Failed to run TTP hunt: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)


@purple_team_app.command("emulate-actor")
def emulate_actor_cli(
    actor_name: str = typer.Argument(
        ..., 
        help="The name of the threat actor to emulate (e.g., 'APT29')."
    ),
    target: str = typer.Argument(
        ..., 
        help="The target domain to test this actor's TTPs against."
    )
):
    """
    Tests defenses against all known TTPs of a *specific threat actor*.
    """
    console.print(f"[bold green]Starting Threat Actor Emulation for {actor_name} against {target}[/bold green]")
    report = {
        "exercise_type": "actor_emulation",
        "actor_name": actor_name,
        "target": target,
        "actor_ttps": None,
        "ttp_coverage_report": []
    }
    
    try:
        # 1. Get Actor TTPs
        # NOTE: Assuming function name
        ttps = ttp_mapper.get_ttps_for_actor(actor_name)
        if not ttps:
            console.secho(f"Could not find TTPs for actor: {actor_name}", fg=typer.colors.RED)
            raise typer.Exit(code=1)
        report["actor_ttps"] = ttps
        console.print(f"[cyan]Found {len(ttps)} TTPs for {actor_name}. Hunting...[/cyan]")

        # 2. Loop and run a "hunt-ttp" for each TTP
        # (This is a simplified version; a real one would be more efficient)
        for ttp in ttps:
            ttp_id = ttp.get("id", "Unknown")
            console.print(f"\n--- Hunting TTP: {ttp_id} ---")
            
            # This is a basic re-use of the `hunt-ttp` logic
            # In a production system, this would be refactored into a shared helper
            ttp_report = {
                "ttp_id": ttp_id,
                "defensive_findings": {},
                "ai_assessment": "SKIPPED - Run 'hunt-ttp' for full details."
            }
            if ttp_id in ("T1566", "T1566.001", "T1566.002"):
                ttp_report["defensive_findings"]["typosquatting"] = defensive.find_typosquatting_dnstwist(target).model_dump()
            elif ttp_id in ("T1190", "T1133"):
                 if API_KEYS.shodan_api_key:
                    ttp_report["defensive_findings"]["attack_surface"] = defensive.analyze_attack_surface_shodan(f"domain:\"{target}\"", API_KEYS.shodan_api_key).model_dump()
            
            report["ttp_coverage_report"].append(ttp_report)

        console.secho(f"\n--- Emulation Complete ---", fg=typer.colors.GREEN, bold=True)
        typer.echo(json.dumps(report, indent=4, default=str))

    except Exception as e:
        logger.error(f"Failed to execute actor emulation: {e}", exc_info=True)
        console.secho(f"Error: Failed to run actor emulation: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)