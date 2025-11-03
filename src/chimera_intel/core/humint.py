"""
HUMINT (Human Intelligence) Module for Chimera Intel.

Allows for the structured storage, retrieval, and AI-powered analysis of
qualitative, human-derived intelligence reports.
"""

import typer
from typing import Optional, Dict, Any
import psycopg2
import random
from .schemas import HumintScenario
from .database import get_db_connection
from .ai_core import generate_swot_from_data
from .config_loader import API_KEYS
from .utils import console
from .schemas import HumintScenario
from .database import get_db_connection
from .ai_core import generate_swot_from_data
from chimera_intel.core.schemas import AiCoreResult
from .config_loader import API_KEYS
from .utils import console
from rich.panel import Panel # For better output

# --- HUMINT SCENARIO COMPONENTS (Integrated with System Dependencies) ---


def run_humint_scenario(scenario: HumintScenario) -> Dict[str, Any]:
    """
    Executes a high-fidelity simulation of a HUMINT scenario.

    This function simulates a multi-stage operational pipeline:
    1. Dynamic Risk Assessment (Opsec score used for calculation)
    2. Operational Execution (Probabilistic success based on PoS)
    3. AI-Powered Final Synthesis (Structured report generation via AI Core dependency)
    """
    console.print(
        f"\n[bold magenta]INITIATING OPERATION:[/bold magenta] {scenario.scenario_type.upper()} against '{scenario.target}'"
    )

    # 1. DYNAMIC RISK ASSESSMENT: Calculates Probability of Success (PoS)
    # Target Opsec score derived from target name (simulates external complexity input)

    target_opsec_score = (sum(ord(c) for c in scenario.target) % 10) + 1

    # Base risk defined by scenario type

    scenario_risk = {
        "infiltration": 0.75,
        "elicitation": 0.55,
        "recruitment": 0.85,
        "deception": 0.45,
    }.get(scenario.scenario_type.lower(), 0.60)

    # Calculate Probability of Success (PoS)

    prob_success = max(0.1, min(0.9, 1.0 - (scenario_risk + (target_opsec_score / 20))))

    # 2. OPERATIONAL EXECUTION: Probabilistic outcome based on PoS

    if random.random() < prob_success:
        success = True
        raw_intelligence = f"Successful collection of data from target '{scenario.target}'. Key personnel, communication schedules, and recent financial data were acquired."
        op_status = "Successful Collection"
    else:
        success = False
        raw_intelligence = f"Operation compromised. Agent withdrew upon detecting advanced Opsec protocols and counter-surveillance by '{scenario.target}'."
        op_status = "Operational Compromise"
    # 3. AI-POWERED FINAL SYNTHESIS: Dependent on AI Core connection

    api_key = API_KEYS.google_api_key

    if not api_key:
        # If API key is missing, report the operational block as a real system error

        ai_synthesis = "AI Synthesis Failed: Google API key not configured for real-time analysis. Cannot generate final report."
        recommendation = "Resolve API Configuration Error."
        key_finding = f"Operational Status: {op_status}. Raw intelligence collected: {raw_intelligence}"
    else:
        # Prepare prompt for the AI Core's synthesis function (generate_swot_from_data)

        ai_prompt = f"""
        Analyze the following operational result for a HUMINT operation:
        Operation Type: {scenario.scenario_type} | Target: {scenario.target}
        Operational Status: {op_status} | PoS: {prob_success:.2f} | Opsec Score: {target_opsec_score}

        Raw Field Intelligence: "{raw_intelligence}"

        Synthesize an actionable intelligence summary, assess the immediate threat/opportunity, 
        and provide a definitive next step recommendation.
        """

        # Call the actual AI Core's synthesis function

        ai_result = generate_swot_from_data(ai_prompt, api_key)

        if ai_result.error:
            ai_synthesis = f"AI Synthesis Failed: Error during analysis: {ai_result.error}. Cannot generate final report."
            recommendation = "Investigate AI Core failure. Review API connectivity and prompt complexity."
            key_finding = f"Operational Status: {op_status}. Raw intelligence collected: {raw_intelligence}"
        else:
            # Use the actual AI-generated analysis text for the synthesis

            ai_synthesis = ai_result.analysis_text
            key_finding = raw_intelligence

            # Set a high-level operational recommendation based on the outcome, directing the user to the detailed AI synthesis.

            if success:
                recommendation = "Review AI Synthesis for detailed next steps. Further action is likely warranted."
            else:
                recommendation = "Review AI Synthesis for Post-Mortem. A revised scenario strategy is recommended."
    # Generate the final report string

    outcome_report = f"""
    **OPERATIONAL SUMMARY: HUMINT SCENARIO - {scenario.scenario_type.upper()}**

    * **Target**: {scenario.target}
    * **Target Opsec Score**: {target_opsec_score}/10
    * **Scenario Base Risk**: {scenario_risk:.2f}
    * **Calculated PoS (Probability of Success)**: {prob_success:.2f}
    * **Operational Status**: {op_status}
    
    ---
    
    **RAW FIELD REPORT SNIPPET:**
    "{raw_intelligence}"
    
    ---

    {ai_synthesis}

    * **Key Finding**: {key_finding}
    * **Next Action Recommendation**: {recommendation}
    """

    console.print(
        f"[bold blue]Status:[/bold blue] {'SUCCESSFUL' if success else 'COMPROMISED'}"
    )
    console.print(
        "[bold yellow]Next Step:[/bold yellow] Disseminate intelligence via Project Manager module."
    )

    return {
        "success": success,
        "outcome": outcome_report,
        "probability_of_success": prob_success,
        "target_opsec_score": target_opsec_score,
    }


# --- END OF HUMINT SCENARIO COMPONENTS ---


humint_app = typer.Typer(
    name="humint",
    help="Manages Human Intelligence (HUMINT) sources and reports.",
)

# The rest of the original database and CLI functions are unchanged.


def add_humint_source(name: str, reliability: str, expertise: str) -> None:
    """Adds a new HUMINT source to the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO humint_sources (name, reliability, expertise) VALUES (%s, %s, %s)",
            (name, reliability, expertise),
        )
        conn.commit()
        cursor.close()
        conn.close()
        console.print(
            f"[bold green]Successfully added HUMINT source:[/bold green] {name}"
        )
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not add source: {e}")


def add_humint_report(source_name: str, content: str) -> None:
    """Adds a new HUMINT report linked to a source."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # First, get the source ID

        cursor.execute("SELECT id FROM humint_sources WHERE name = %s", (source_name,))
        source_record = cursor.fetchone()
        if not source_record:
            console.print(
                f"[bold red]Error:[/bold red] Source '{source_name}' not found."
            )
            return
        source_id = source_record[0]
        cursor.execute(
            "INSERT INTO humint_reports (source_id, content) VALUES (%s, %s)",
            (source_id, content),
        )
        conn.commit()
        cursor.close()
        conn.close()
        console.print(
            f"[bold green]Successfully added HUMINT report from source:[/bold green] {source_name}"
        )
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not add report: {e}")

def simulate_social_elicitation(
    target_persona_desc: str, 
    goal: str,
    operative_persona: str = "A curious industry colleague"
) -> AiCoreResult:
    """
    Uses the AI Core to simulate a social interaction for intel gathering.
    """
    console.print(f"[bold magenta]INITIATING VIRTUAL HUMINT SIMULATION[/bold magenta]")
    
    api_key = API_KEYS.google_api_key
    if not api_key:
        console.print("[bold red]Error:[/bold red] Google API key not configured.")
        return AiCoreResult(
            analysis_text="", 
            error="Google API key not configured."
        )

    ai_prompt = f"""
    You are a professional intelligence analyst running a simulation.
    Your task is to generate a realistic, simulated social media or chat conversation.

    **Simulation Parameters:**
    
    1.  **Your Operative's Persona:** {operative_persona}
    2.  **Target's Persona:** {target_persona_desc}
    3.  **Your Goal:** {goal}

    **Instructions:**
    -   Generate a plausible, multi-turn dialogue (at least 5-7 exchanges).
    -   The operative should attempt to subtly elicit information related to the goal, without being overt.
    -   The target should respond in character, potentially being guarded or helpful, depending on the persona.
    -   Format the output as a script (e.g., "Operative: ...", "Target: ...").
    -   Conclude the simulation with a one-paragraph summary: "[SIMULATION SUMMARY] ..."
    """

    console.print(f"  - [cyan]Goal:[/cyan] {goal}")
    console.print(f"  - [cyan]Target Persona:[/cyan] {target_persona_desc}")
    
    with console.status("[bold yellow]Running virtual operative simulation...[/bold yellow]"):
        ai_result = generate_swot_from_data(ai_prompt, api_key)

    if ai_result.error:
        console.print(f"[bold red]AI Simulation Error:[/bold red] {ai_result.error}")
    else:
        console.print(Panel(
            ai_result.analysis_text,
            title="[bold green]Virtual HUMINT Simulation Log[/bold green]",
            border_style="green"
        ))
        
    return ai_result

def analyze_humint_reports(topic: str) -> Optional[str]:
    """Uses AI to analyze all HUMINT reports related to a specific topic."""
    api_key = API_KEYS.google_api_key
    if not api_key:
        console.print("[bold red]Error:[/bold red] Google API key not configured.")
        return None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # This is a simple text search; a real implementation might use more advanced NLP

        cursor.execute(
            "SELECT s.name, s.reliability, r.content FROM humint_reports r JOIN humint_sources s ON r.source_id = s.id WHERE r.content ILIKE %s",
            (f"%{topic}%",),
        )
        records = cursor.fetchall()
        cursor.close()
        conn.close()

        if not records:
            console.print(
                f"[yellow]No HUMINT reports found matching the topic: {topic}[/yellow]"
            )
            return None
        reports_summary = "\n".join(
            [
                f"- Source: {r[0]} (Reliability: {r[1]})\n  - Report: {r[2]}"
                for r in records
            ]
        )

        prompt = f"""
        As an intelligence analyst, synthesize the following raw human intelligence (HUMINT) reports.
        Your task is to produce a concise intelligence summary based on the provided data.
        Identify key themes, potential biases based on source reliability, and any actionable insights.

        **Raw HUMINT Reports:**
        {reports_summary}
        """

        # In a real environment, this line would be executed:

        ai_result = generate_swot_from_data(prompt, api_key)

        if ai_result.error:
            console.print(f"[bold red]AI Analysis Error:[/bold red] {ai_result.error}")
            return None
        return ai_result.analysis_text
    except (psycopg2.Error, ConnectionError) as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not analyze reports: {e}"
        )
        return None


@humint_app.command("add-source")
def cli_add_source(
    name: str = typer.Option(
        ..., "--name", "-n", help="The unique name or codename of the source."
    ),
    reliability: str = typer.Option(
        ..., "--reliability", "-r", help="Reliability code (e.g., A1, B2)."
    ),
    expertise: str = typer.Option(
        ...,
        "--expertise",
        "-e",
        help="Area of expertise (e.g., 'Cybercrime', 'Geopolitics').",
    ),
):
    """Adds a new HUMINT source to the database."""
    add_humint_source(name, reliability, expertise)


@humint_app.command("add-report")
def cli_add_report(
    source_name: str = typer.Option(
        ..., "--source", "-s", help="The name of the source providing the report."
    ),
    content: str = typer.Option(
        ...,
        "--content",
        "-c",
        help="The content of the intelligence report.",
        prompt=True,
    ),
):
    """Adds a new HUMINT report from a specified source."""
    add_humint_report(source_name, content)


@humint_app.command("analyze")
def cli_analyze(
    topic: str = typer.Argument(
        ..., help="The topic or keyword to analyze across all HUMINT reports."
    )
):
    """Analyzes all HUMINT reports related to a specific topic."""
    analysis = analyze_humint_reports(topic)
    if analysis:
        console.print(
            f"\n[bold green]AI-Powered HUMINT Analysis for '{topic}':[/bold green]"
        )
        console.print(analysis)

@humint_app.command("simulate-social") 
def cli_simulate_social_elicitation(
    target_persona: str = typer.Option(
        ..., "--target", help="A description of the target's persona."
    ),
    goal: str = typer.Option(
        ..., "--goal", help="The specific piece of information the operative is trying to elicit."
    ),
    operative_persona: str = typer.Option(
        "A curious industry colleague", 
        "--operative", 
        help="The persona the virtual operative should adopt."
    )
):
    """
    (NEW) Runs a virtual HUMINT simulation of a social interaction.
    """
    simulate_social_elicitation(
        target_persona_desc=target_persona,
        goal=goal,
        operative_persona=operative_persona
    )
