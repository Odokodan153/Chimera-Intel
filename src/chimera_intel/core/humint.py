"""
HUMINT (Human Intelligence) Module for Chimera Intel.

Allows for the structured storage, retrieval, and AI-powered analysis of
qualitative, human-derived intelligence reports.

This module now includes:
1.  Original simulation and basic reporting functions.
2.  Practical roadmap functions (Source Registry, PII Encryption).
3.  Validation workflows and network analysis functions.
4.  Audio-to-text transcription for field reports.
5.  Automatic Entity Extraction and Linking.
6.  (FINAL) Integration with Forensic Vault and Role-Based Access Control.
"""

import typer
from typing import Optional, Dict, Any, List, Set
import psycopg2
import random
from datetime import datetime
from pathlib import Path 
from .schemas import FieldReportIntake
try:
    from textblob import TextBlob
    NLP_AVAILABLE = True
except ImportError:
    NLP_AVAILABLE = False
try:
    import speech_recognition as sr
    SPEECH_RECOGNITION_AVAILABLE = True
except ImportError:
    SPEECH_RECOGNITION_AVAILABLE = False
from .schemas import HumintScenario
from .database import get_db_connection
from .ai_core import generate_swot_from_data
from .config_loader import API_KEYS
from .utils import console
from .schemas import HumintScenario
from .database import get_db_connection
from .ai_core import generate_swot_from_data
from chimera_intel.core.schemas import AiCoreResult, HumintNetworkLink, HumintSourceDetails, User
from .config_loader import API_KEYS
from .utils import console
from rich.panel import Panel 
from rich.table import Table 
from . import security_utils
from .forensic_vault import get_vault
from .user_manager import get_current_active_user 


def _extract_and_link_entities(
    report_id: int, 
    source_name: str, 
    content: str, 
    manual_entities: List[str]
) -> List[str]:
    """
    (NEW) Extracts entities from text and auto-links them in the network.
    (Implements: Entity Extraction)
    """
    if not NLP_AVAILABLE:
        console.print("[yellow]Warning:[/yellow] 'textblob' not installed. Skipping auto-entity extraction.")
        return manual_entities
        
    console.print("Running automatic entity extraction...")
    blob = TextBlob(content)
    
    all_entities: Set[str] = set(e.strip() for e in manual_entities)
    auto_entities = 0
    
    for phrase in blob.noun_phrases:
        if (1 < len(phrase.split()) < 4) and not phrase.islower():
            if phrase not in all_entities:
                all_entities.add(phrase)
                auto_entities += 1
                map_network_link(
                    entity_a=source_name,
                    relationship="Reported on",
                    entity_b=phrase,
                    source_report_id=report_id
                )

    console.print(f"Automatically extracted and linked {auto_entities} new entities.")
    return sorted(list(all_entities))



def run_humint_scenario(scenario: HumintScenario) -> Dict[str, Any]:
    """
    (Original) Executes a high-fidelity simulation of a HUMINT scenario.
    """
    console.print(
        f"\n[bold magenta]INITIATING OPERATION:[/bold magenta] {scenario.scenario_type.upper()} against '{scenario.target}'"
    )

    # 1. DYNAMIC RISK ASSESSMENT
    target_opsec_score = (sum(ord(c) for c in scenario.target) % 10) + 1
    scenario_risk = {
        "infiltration": 0.75, "elicitation": 0.55, "recruitment": 0.85, "deception": 0.45,
    }.get(scenario.scenario_type.lower(), 0.60)
    prob_success = max(0.1, min(0.9, 1.0 - (scenario_risk + (target_opsec_score / 20))))

    # 2. OPERATIONAL EXECUTION
    if random.random() < prob_success:
        success = True
        raw_intelligence = f"Successful collection of data from target '{scenario.target}'. Key personnel, communication schedules, and recent financial data were acquired."
        op_status = "Successful Collection"
    else:
        success = False
        raw_intelligence = f"Operation compromised. Agent withdrew upon detecting advanced Opsec protocols and counter-surveillance by '{scenario.target}'."
        op_status = "Operational Compromise"
        
    # 3. AI-POWERED FINAL SYNTHESIS
    api_key = API_KEYS.google_api_key
    if not api_key:
        ai_synthesis = "AI Synthesis Failed: Google API key not configured for real-time analysis. Cannot generate final report."
        recommendation = "Resolve API Configuration Error."
        key_finding = f"Operational Status: {op_status}. Raw intelligence collected: {raw_intelligence}"
    else:
        ai_prompt = f"""
        Analyze the following operational result for a HUMINT operation:
        Operation Type: {scenario.scenario_type} | Target: {scenario.target}
        Operational Status: {op_status} | PoS: {prob_success:.2f} | Opsec Score: {target_opsec_score}
        Raw Field Intelligence: "{raw_intelligence}"
        Synthesize an actionable intelligence summary, assess the immediate threat/opportunity, 
        and provide a definitive next step recommendation.
        """
        ai_result = generate_swot_from_data(ai_prompt, api_key)

        if ai_result.error:
            ai_synthesis = f"AI Synthesis Failed: Error during analysis: {ai_result.error}. Cannot generate final report."
            recommendation = "Investigate AI Core failure. Review API connectivity and prompt complexity."
            key_finding = f"Operational Status: {op_status}. Raw intelligence collected: {raw_intelligence}"
        else:
            ai_synthesis = ai_result.analysis_text
            key_finding = raw_intelligence
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
    return {
        "success": success,
        "outcome": outcome_report,
        "probability_of_success": prob_success,
        "target_opsec_score": target_opsec_score,
    }


# --- ORIGINAL (BASIC) DATABASE AND CLI FUNCTIONS ---

humint_app = typer.Typer(
    name="humint",
    help="Manages Human Intelligence (HUMINT) sources, reports, and simulations.",
)

def add_humint_source(name: str, reliability: str, expertise: str) -> None:
    """(Original) Adds a new HUMINT source to the database (basic version)."""
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
            f"[bold green]Successfully added HUMINT source (basic):[/bold green] {name}"
        )
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not add source: {e}")


def add_humint_report(source_name: str, content: str) -> None:
    """(Original) Adds a new HUMINT report linked to a source (basic version)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
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
            f"[bold green]Successfully added HUMINT report (basic) from source:[/bold green] {source_name}"
        )
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not add report: {e}")

def simulate_social_elicitation(
    target_persona_desc: str, 
    goal: str,
    operative_persona: str = "A curious industry colleague"
) -> AiCoreResult:
    """
    (Original) Uses the AI Core to simulate a social interaction for intel gathering.
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
    -   The target should respond in character.
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
    """(Original) Uses AI to analyze all HUMINT reports related to a specific topic."""
    api_key = API_KEYS.google_api_key
    if not api_key:
        console.print("[bold red]Error:[/bold red] Google API key not configured.")
        return None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
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


# --- (NEW) MVP: PRACTICAL ROADMAP FUNCTIONS ---

def register_source(
    name: str,
    contact_info: str,
    expertise: str,
    initial_reliability: str,
    consent_status: str, # e.g., "Signed", "Pending", "None"
    consent_artifact_path: Optional[str] = None,
    payment_details: Optional[str] = None # Per "payment records"
) -> None:
    """
    (NEW) Registers a new HUMINT source with consent and PII protection.
    (Implements: Source Registry MVP)
    """
    try:
        encrypted_contact_info = security_utils.encrypt_pii(contact_info)
        encrypted_payment_details = None
        if payment_details:
            encrypted_payment_details = security_utils.encrypt_pii(payment_details)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO humint_sources 
            (name, reliability, expertise, encrypted_contact, encrypted_payment_details,
             consent_status, consent_artifact_path, registered_on) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (name, initial_reliability, expertise, encrypted_contact_info, 
             encrypted_payment_details, consent_status, consent_artifact_path, datetime.now())
        )
        conn.commit()
        cursor.close()
        conn.close()
        console.print(
            f"[bold green]Successfully registered new HUMINT source:[/bold green] {name} (Consent: {consent_status})"
        )
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not register source: {e}")
    except Exception as e:
        console.print(f"[bold red]Operation Failed:[/bold red] Could not register source: {e}")


def submit_field_report(source_name: str, intake: FieldReportIntake) -> Optional[int]:
    """
    (UPDATED) Submits a structured HUMINT field report from a source.
    
    This function now:
    1.  Automatically calls _extract_and_link_entities (NLP).
    2.  (NEW) Stores immutable evidence in the Forensic Vault.
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM humint_sources WHERE name = %s", (source_name,))
        source_record = cursor.fetchone()
        
        if not source_record:
            console.print(f"[bold red]Error:[/bold red] Source '{source_name}' not found.")
            return None
        
        source_id = source_record[0]
        
        # 1. Insert the report first to get an ID
        cursor.execute(
            """
            INSERT INTO humint_reports 
            (source_id, content, report_type, tags, metadata, reported_on) 
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (source_id, intake.content, intake.report_type, 
             intake.tags, 
             psycopg2.extras.Json(intake.metadata) if intake.metadata else None, 
             datetime.now())
        )
        new_report_id = cursor.fetchone()[0]
        
        # 2. (NEW) Store immutable evidence in Forensic Vault
        try:
            vault = get_vault()
            vault_metadata = {
                "source_name": source_name,
                "report_id": new_report_id,
                "report_type": intake.report_type,
                "tags": intake.tags,
            }
            vault.store_evidence(
                content=intake.content.encode('utf-8'), # Store as bytes
                content_type="text/plain",
                file_name=f"humint_report_{new_report_id}.txt",
                metadata=vault_metadata
            )
            console.print(f"Successfully logged report {new_report_id} to Forensic Vault.")
        except Exception as e:
            # Don't fail the whole transaction, just log the error
            console.print(f"[bold yellow]Warning:[/bold yellow] Failed to log evidence to Forensic Vault: {e}")
        
        # 3. Run entity extraction
        final_entities = _extract_and_link_entities(
            report_id=new_report_id,
            source_name=source_name,
            content=intake.content,
            manual_entities=intake.entities_mentioned
        )
        
        # 4. Update the report with the combined entity list
        cursor.execute(
            "UPDATE humint_reports SET entities = %s WHERE id = %s",
            (final_entities, new_report_id)
        )
        
        conn.commit()
        console.print(
            f"[bold green]Successfully submitted field report (ID: {new_report_id}) from source:[/bold green] {source_name}"
        )
        return new_report_id
        
    except (psycopg2.Error, ConnectionError) as e:
        if conn:
            conn.rollback()
        console.print(f"[bold red]Database Error:[/bold red] Could not submit report: {e}")
        return None
    finally:
        if conn:
            cursor.close()
            conn.close()

def map_network_link(
    entity_a: str,
    relationship: str,
    entity_b: str,
    source_report_id: Optional[int] = None
) -> None:
    """
    (NEW) Maps a relationship between two human-network entities.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO humint_network_links 
            (entity_a, relationship, entity_b, source_report_id, created_on) 
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (entity_a, relationship, entity_b) DO NOTHING
            """,
            (entity_a, relationship, entity_b, source_report_id, datetime.now())
        )
        conn.commit()
        cursor.close()
        conn.close()
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not map link: {e}")


# --- (NEW) MVP: VALIDATION, ANALYSIS, AND ACCESS CONTROL ---

def get_source_details(source_name: str, current_user: User) -> Optional[HumintSourceDetails]:
    """
    (NEW) Gets detailed information for a source, redacting PII based on user role.
    (Implements: Role-Based Redaction)
    """
    try:
        conn = get_db_connection()
        # Use DictCursor to get column names
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(
            "SELECT * FROM humint_sources WHERE name = %s", (source_name,)
        )
        record = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not record:
            console.print(f"[bold red]Error:[/bold red] Source '{source_name}' not found.")
            return None
            
        # (NEW) Role-based redaction logic
        # These roles are assumed. In a real system, this would be a config.
        allowed_roles = ["Administrator", "CaseOfficer", "Manager"]
        contact_info = "[REDACTED]"
        payment_details = "[REDACTED]"

        if current_user.role in allowed_roles:
            try:
                if record["encrypted_contact"]:
                    contact_info = security_utils.decrypt_pii(record["encrypted_contact"])
                if record["encrypted_payment_details"]:
                    payment_details = security_utils.decrypt_pii(record["encrypted_payment_details"])
            except Exception as e:
                console.print(f"[bold red]PII Decryption Failed for user {current_user.username}: {e}[/bold red]")
                contact_info = "[DECRYPTION FAILED]"
                payment_details = "[DECRYPTION FAILED]"
        
        # Use Pydantic model for structured, validated output
        return HumintSourceDetails(
            id=record["id"],
            name=record["name"],
            reliability=record["reliability"],
            expertise=record["expertise"],
            consent_status=record.get("consent_status", "N/A"),
            contact_info=contact_info,
            payment_details=payment_details
        )
        
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not get source details: {e}")
        return None
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")
        return None


def validate_report(
    report_id: int,
    status: str,
    comments: str,
    analyst_name: str,
    new_reliability_for_source: Optional[str] = None
) -> None:
    """
    (NEW) Validates a report and optionally updates its source's reliability.
    (Implements: Validation Workflow MVP)
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Log the validation event
        cursor.execute(
            """
            INSERT INTO humint_validation_logs 
            (report_id, validation_status, comments, analyst_name, validated_on)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (report_id, status, comments, analyst_name, datetime.now())
        )
        
        source_id = None
        # 2. If a new reliability is provided, update the source
        if new_reliability_for_source:
            cursor.execute("SELECT source_id FROM humint_reports WHERE id = %s", (report_id,))
            source_record = cursor.fetchone()
            if not source_record:
                console.print(f"[bold red]Error:[/bold red] Report ID {report_id} not found.")
                conn.rollback()
                return
            
            source_id = source_record[0]
            cursor.execute(
                "UPDATE humint_sources SET reliability = %s WHERE id = %s",
                (new_reliability_for_source, source_id)
            )
            cursor.execute(
                """
                INSERT INTO humint_reliability_logs
                (source_id, new_reliability, justification, analyst_name, changed_on)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (source_id, new_reliability_for_source, 
                 f"Validation of report {report_id}: {comments}", 
                 analyst_name, datetime.now())
            )
        
        conn.commit()
        console.print(f"[bold green]Successfully validated report {report_id} with status: {status}[/bold green]")
        if new_reliability_for_source and source_id:
             console.print(f"Updated reliability for source (ID: {source_id}) to: {new_reliability_for_source}")
             
    except (psycopg2.Error, ConnectionError) as e:
        if conn:
            conn.rollback()
        console.print(f"[bold red]Database Error:[/bold red] Could not validate report: {e}")
    finally:
        if conn:
            cursor.close()
            conn.close()

def find_entity_links(entity_name: str) -> List[HumintNetworkLink]:
    """
    (NEW) Finds all 1st-degree network links for a given entity.
    (Implements: Human Network Mapper MVP - Read)
    """
    links = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        query_name = f"%{entity_name}%"
        cursor.execute(
            """
            SELECT id, entity_a, relationship, entity_b, source_report_id, created_on 
            FROM humint_network_links
            WHERE entity_a ILIKE %s OR entity_b ILIKE %s
            ORDER BY created_on DESC
            """,
            (query_name, query_name)
        )
        
        records = cursor.fetchall()
        for record in records:
            links.append(HumintNetworkLink.from_orm(record))
            
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not query network links: {e}")
    finally:
        if 'conn' in locals() and conn:
            cursor.close()
            conn.close()
            
    return links

# --- (NEW) AUDIO TRANSCRIPTION FUNCTION ---

def transcribe_audio_report(audio_file_path: Path) -> str:
    """
    (NEW) Transcribes content from an audio file (.wav, .aiff, .flac).
    (Implements: Audio/Text Transcription)
    """
    if not SPEECH_RECOGNITION_AVAILABLE:
        console.print("[bold red]Error:[/bold red] 'SpeechRecognition' library not installed.")
        raise ImportError("SpeechRecognition library not found.")
        
    if not audio_file_path.exists():
        raise FileNotFoundError(f"Audio file not found at: {audio_file_path}")

    recognizer = sr.Recognizer()
    
    try:
        with sr.AudioFile(str(audio_file_path)) as source:
            audio_data = recognizer.record(source)
        
        console.print(f"Transcribing audio file: {audio_file_path.name}...")
        text = recognizer.recognize_google(audio_data)
        return text
        
    except sr.UnknownValueError:
        console.print("[bold yellow]Warning:[/bold yellow] Google Speech Recognition could not understand audio.")
        return ""
    except sr.RequestError as e:
        console.print(f"[bold red]Error:[/bold red] Could not request results from Google Speech Recognition service; {e}")
        return ""
    except Exception as e:
        console.print(f"[bold red]Audio Transcription Error:[/bold red] {e}")
        return ""


# --- ORIGINAL CLI COMMANDS ---

@humint_app.command("add-source")
def cli_add_source(
    name: str = typer.Option(..., "--name", "-n", help="Name/codename of the source."),
    reliability: str = typer.Option(..., "--reliability", "-r", help="Reliability code (e.g., A1)."),
    expertise: str = typer.Option(..., "--expertise", "-e", help="Area of expertise."),
):
    """(Original) Adds a new HUMINT source to the database (basic)."""
    add_humint_source(name, reliability, expertise)


@humint_app.command("add-report")
def cli_add_report(
    source_name: str = typer.Option(..., "--source", "-s", help="Name of the source."),
    content: str = typer.Option(..., "--content", "-c", help="Content of the report.", prompt=True),
):
    """(Original) Adds a new HUMINT report from a specified source (basic)."""
    add_humint_report(source_name, content)


@humint_app.command("analyze")
def cli_analyze(
    topic: str = typer.Argument(..., help="Topic/keyword to analyze across reports.")
):
    """(Original) Analyzes all HUMINT reports related to a specific topic."""
    analysis = analyze_humint_reports(topic)
    if analysis:
        console.print(
            f"\n[bold green]AI-Powered HUMINT Analysis for '{topic}':[/bold green]"
        )
        console.print(analysis)

@humint_app.command("simulate-social") 
def cli_simulate_social_elicitation(
    target_persona: str = typer.Option(..., "--target", help="Description of the target's persona."),
    goal: str = typer.Option(..., "--goal", help="The information to elicit."),
    operative_persona: str = typer.Option(
        "A curious industry colleague", 
        "--operative", 
        help="The persona the virtual operative should adopt."
    )
):
    """(Original) Runs a virtual HUMINT simulation of a social interaction."""
    simulate_social_elicitation(
        target_persona_desc=target_persona,
        goal=goal,
        operative_persona=operative_persona
    )

# --- (NEW) MVP CLI COMMANDS ---

# (NEW) Helper function to get the current user for CLI commands
# In a real app, this would be a proper dependency injection
def get_cli_user() -> User:
    try:
        # Try to get the real user (if they are logged in via web UI)
        # This is a placeholder for a more complex auth flow.
        user = get_current_active_user(user_db=None) # type: ignore
        console.print(f"[cyan]Running as User: {user.username} (Role: {user.role})[/cyan]")
        return user
    except Exception:
        # Fallback for CLI-only context
        console.print("[yellow]MOCK AUTH: No active session. Running as 'admin' (Administrator)[/yellow]")
        return User(
            username="admin", 
            role="Administrator", 
            full_name="Admin User", 
            email="admin@chimera.local", 
            disabled=False,
            hashed_password="x" # Hashed password is required by schema
        )

@humint_app.command("register-source")
def cli_register_source(
    name: str = typer.Option(..., "--name", "-n", help="Name/codename of the source."),
    contact_info: str = typer.Option(..., "--contact", help="Contact info (email/phone). Will be encrypted.", prompt=True, hide_input=True),
    expertise: str = typer.Option(..., "--expertise", "-e", help="Area of expertise."),
    reliability: str = typer.Option("C3", "--reliability", "-r", help="Initial reliability code."),
    consent_status: str = typer.Option(..., "--consent", help="Consent status (e.g., 'Signed', 'Pending')."),
    consent_path: Optional[str] = typer.Option(None, "--consent-doc", help="Path to consent artifact."),
    payment_details: Optional[str] = typer.Option(None, "--payment", help="Payment details. Will be encrypted.", hide_input=True)
):
    """(NEW) Registers a new HUMINT source with PII encryption and consent tracking."""
    if payment_details is None:
        payment_input = typer.prompt("Enter payment details (optional, will be hidden)", default="", hide_input=True)
        payment_details = payment_input if payment_input else None

    register_source(
        name, 
        contact_info, 
        expertise, 
        reliability, 
        consent_status, 
        consent_path,
        payment_details
    )

@humint_app.command("get-source")
def cli_get_source(
    name: str = typer.Argument(..., help="The name of the source to retrieve."),
    current_user: User = typer.Depends(get_cli_user)
):
    """(NEW) Gets source details, redacting PII based on user role."""
    
    details = get_source_details(name, current_user)
    
    if details:
        console.print(f"\n[bold]HUMINT Source Details: {details.name}[/bold]")
        table = Table(show_header=False, box=None)
        table.add_column()
        table.add_column()
        table.add_row("[bold cyan]Reliability[/bold cyan]", details.reliability)
        table.add_row("[bold cyan]Expertise[/bold cyan]", details.expertise)
        table.add_row("[bold cyan]Consent[/bold cyan]", details.consent_status)
        
        # (NEW) Render redacted or plaintext PII based on role
        pii_style = "default" if "[REDACTED]" in details.contact_info else "bold red"
        table.add_row("[bold cyan]Contact Info[/bold cyan]", f"[{pii_style}]{details.contact_info}[/{pii_style}]")
        table.add_row("[bold cyan]Payment Info[/bold cyan]", f"[{pii_style}]{details.payment_details or 'N/A'}[/{pii_style}]")
        
        console.print(table)


@humint_app.command("submit-report")
def cli_submit_report(
    source_name: str = typer.Option(..., "--source", "-s", help="Name of the source."),
    report_type: str = typer.Option("Interview", "--type", help="Type of report (e.g., 'Interview')."),
    content: str = typer.Option(..., "--content", "-c", help="Content of the report.", prompt=True),
    entities: Optional[List[str]] = typer.Option(None, "--entity", help="(Optional) Manually add a key entity. (Repeatable)"),
    tags: Optional[List[str]] = typer.Option(None, "--tag", help="Tag for the report. (Repeatable)")
):
    """
    (UPDATED) Submits a structured field report.
    
    This command now auto-extracts entities and logs to the Forensic Vault.
    """
    if not NLP_AVAILABLE:
        console.print("[bold yellow]Warning:[/bold yellow] 'textblob' not installed. Auto-extraction will be skipped.")
        
    intake_data = FieldReportIntake(
        report_type=report_type,
        content=content,
        entities_mentioned=entities or [],
        tags=tags or []
    )
    submit_field_report(source_name, intake_data)

@humint_app.command("map-link")
def cli_map_link(
    entity_a: str = typer.Option(..., "--from", help="The source entity."),
    relationship: str = typer.Option(..., "--rel", help="The relationship (e.g., 'Worked with')."),
    entity_b: str = typer.Option(..., "--to", help="The target entity."),
    report_id: Optional[int] = typer.Option(None, "--report-id", help="Optional ID of the source report.")
):
    """(NEW) Manually maps a human-network relationship between two entities."""
    map_network_link(entity_a, relationship, entity_b, report_id)

@humint_app.command("validate-report")
def cli_validate_report(
    report_id: int = typer.Argument(..., help="The ID of the report to validate."),
    status: str = typer.Option(..., "--status", help="Validation status (e.g., 'Confirmed', 'Inaccurate')."),
    comments: str = typer.Option(..., "--comments", help="Validation comments.", prompt=True),
    analyst_name: str = typer.Option(..., "--analyst", help="Name of the analyst."),
    new_reliability: Optional[str] = typer.Option(None, "--update-reliability", help="[Optional] New reliability code for the source.")
):
    """(NEW) Logs a validation check for a report and updates source reliability."""
    validate_report(report_id, status, comments, analyst_name, new_reliability)

@humint_app.command("find-links")
def cli_find_links(
    entity: str = typer.Argument(..., help="The entity name to search for.")
):
    """(NEW) Finds and displays all 1st-degree network links for an entity."""
    console.print(f"\n[bold]Finding network links for: {entity}[/bold]")
    links = find_entity_links(entity)
    
    if not links:
        console.print(f"[yellow]No network links found for '{entity}'.[/yellow]")
        return
        
    table = Table(title=f"Network Links for '{entity}'")
    table.add_column("ID", style="dim")
    table.add_column("Entity A", style="cyan")
    table.add_column("Relationship", style="magenta")
    table.add_column("Entity B", style="cyan")
    table.add_column("Source Report", style="yellow")

    for link in links:
        entity_a_str = f"[bold]{link.entity_a}[/bold]" if entity.lower() in link.entity_a.lower() else link.entity_a
        entity_b_str = f"[bold]{link.entity_b}[/bold]" if entity.lower() in link.entity_b.lower() else link.entity_b
        table.add_row(
            str(link.id),
            entity_a_str,
            link.relationship,
            entity_b_str,
            str(link.source_report_id) if link.source_report_id else "N/A"
        )
    console.print(table)

@humint_app.command("submit-audio-report")
def cli_submit_audio_report(
    source_name: str = typer.Option(..., "--source", "-s", help="Name of the source."),
    audio_file: Path = typer.Option(
        ..., "--file",
        help="Path to the audio file (.wav, .flac, .aiff).",
        exists=True, file_okay=True, readable=True
    ),
    report_type: str = typer.Option("Audio Debrief", "--type", help="Type of report."),
    entities: Optional[List[str]] = typer.Option(None, "--entity", help="(Optional) Manually add a key entity."),
    tags: Optional[List[str]] = typer.Option(None, "--tag", help="Tag for the report.")
):
    """
    (NEW) Transcribes an audio file and submits it as a field report.
    
    This command now also auto-extracts entities and logs to the Forensic Vault.
    """
    if not SPEECH_RECOGNITION_AVAILABLE:
        console.print("[bold red]Error: 'SpeechRecognition' is required.[/bold red]")
        raise typer.Exit(code=1)
        
    try:
        with console.status("[bold yellow]Transcribing audio...[/bold yellow]"):
            content = transcribe_audio_report(audio_file)
        
        if not content:
            console.print("[bold red]Transcription failed. Report not submitted.[/bold red]")
            raise typer.Exit(code=1)
            
        console.print("[bold green]Transcription Successful:[/bold green]")
        console.print(Panel(content, title="Transcribed Content"))
        
        if not typer.confirm("Submit this transcription as a report?"):
            console.print("Submission cancelled.")
            raise typer.Exit()
            
        intake_data = FieldReportIntake(
            report_type=report_type,
            content=content,
            entities_mentioned=entities or [],
            tags=tags or ["audio-transcription"],
            metadata={"original_audio_file": str(audio_file)}
        )
        
        # Auto-extraction and vault logging will run inside submit_field_report
        submit_field_report(source_name, intake_data)
        
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")