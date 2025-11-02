"""
Core module for Multi-Modal Data Fusion (4D Analysis).

This module is responsible for:
1.  Entity Resolution & Modeling: Stitching data fragments into a "Master EntityProfile".
2.  Temporal Tracking: Building a "Pattern of Life" from GEOINT, AVINT, MARINT, etc.
3.  Predictive & Cognitive Modeling: Generating predictive and prescriptive insights.

This is a "real" implementation that orchestrates other core modules.
"""

import typer
import re
import json
from typing import Optional, List, Any, Dict, Tuple
from src.chimera_intel.core.schemas import (
    DataFusionResult,
    MasterEntityProfile,
    PatternOfLife,
    PatternOfLifeEvent,
    CognitivePrediction,
    PhysicalLocation,
    SocialProfile,
    # Import result schemas from other modules
    FootprintResult,
    SocialOSINTResult,
    DocketSearchResult,
    AVINTResult,
    DarkWebScanResult,
)
from src.chimera_intel.core.logger_config import get_logger
from datetime import datetime

# --- Core Component Imports ---
from src.chimera_intel.core.graph_db import GraphDatabase
from src.chimera_intel.core.ai_core import AICore

# --- Data Silo Module Imports (for real data collection) ---
# We import the "real" functions from other modules
try:
    from src.chimera_intel.core.footprint import _run_footprint
    from src.chimera_intel.core.social_osint import _run_username_search
    from src.chimera_intel.core.legint import _run_docket_search
    from src.chimera_intel.core.avint import _run_avint_scan
    from src.chimera_intel.core.dark_web_osint import _run_dark_web_search
    MODULES_LOADED = True
except ImportError:
    MODULES_LOADED = False


logger = get_logger(__name__)

app = typer.Typer(
    no_args_is_help=True,
    help="Multi-Modal Data Fusion (4D Analysis) Engine. Fuses data across cyber, physical, and temporal dimensions.",
)

# --- Helper Functions for Target-Typing ---

def _is_domain(target: str) -> bool:
    """Basic check for a domain."""
    return (
        re.match(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$",
            target,
        )
        is not None
    )


def _is_ip(target: str) -> bool:
    """Basic check for an IP address."""
    return (
        re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", target) is not None
    )


def _is_email(target: str) -> bool:
    """Basic check for an email."""
    return re.match(r"[^@]+@[^@]+\.[^@]+", target) is not None


# --- Core Fusion Pipeline Steps ---

def _collect_and_resolve(
    target: str, graph: GraphDatabase, ai_core: AICore
) -> Tuple[MasterEntityProfile, List[PatternOfLifeEvent]]:
    """
    Step 1: Run collection modules based on target type.
    Step 2: Perform entity resolution, populating the Graph and Master Profile.
    Step 3: Extract temporal events for the Pattern of Life.
    """
    logger.info(f"Starting collection and resolution for target: {target}")
    profile = MasterEntityProfile()
    pol_events: List[PatternOfLifeEvent] = []
    
    # Define a central node for this target entity
    # We use the AI to generate a more stable/abstract ID if needed
    entity_id_prompt = f"Generate a unique, stable entity ID for the target: '{target}'. Example: 'entity-john-doe'."
    entity_id = ai_core.generate_text(entity_id_prompt, max_tokens=50).strip()
    profile.entity_id = entity_id
    profile.primary_name = target # Start with the target as the name
    
    graph.add_node(id=entity_id, type="MasterEntity", label=target, properties={"query": target})

    if not MODULES_LOADED:
        logger.warning("Core modules not found. Fusion will be limited.")
        return profile, pol_events

    # --- Run Data Collection Modules ---

    try:
        # A) Footprint (if Domain or IP)
        if _is_domain(target) or _is_ip(target):
            logger.info(f"Target identified as Domain/IP. Running Footprint.")
            footprint_result: FootprintResult = _run_footprint(target)
            if footprint_result and not footprint_result.error:
                profile.resolved_from_fragments.append(f"CYBINT:Footprint:{target}")
                if footprint_result.footprint.dns_records:
                    ips = footprint_result.footprint.dns_records.get("A", [])
                    profile.linked_cyber_indicators.extend(ips)
                    for ip in ips:
                        graph.add_node(id=ip, type="IPAddress", label=ip)
                        graph.add_edge(entity_id, ip, "RESOLVES_TO")

        # B) Social OSINT (if not IP/Domain)
        if not _is_ip(target):
            logger.info(f"Target not an IP. Running Social OSINT.")
            social_result: SocialOSINTResult = _run_username_search(target)
            if social_result and not social_result.error:
                profile.resolved_from_fragments.append(f"SOCMINT:Username:{target}")
                profile.aliases.append(target)
                for found in social_result.found_profiles:
                    profile.linked_social_profiles.append(found)
                    graph.add_node(id=found.url, type="SocialProfile", label=found.name)
                    graph.add_edge(entity_id, found.url, "HAS_PROFILE")

        # C) Dark Web OSINT
        logger.info(f"Running Dark Web OSINT for all targets.")
        darkweb_result: DarkWebScanResult = _run_dark_web_search(target)
        if darkweb_result and not darkweb_result.error:
            profile.resolved_from_fragments.append(f"DARKWEB:Query:{target}")
            for res in darkweb_result.found_results[:5]: # Limit to top 5
                graph.add_node(id=res.url, type="DarkWebPage", label=res.title)
                graph.add_edge(entity_id, res.url, "MENTIONED_ON")
        
        # D) Legal Intelligence (LEGINT)
        logger.info(f"Running LEGINT docket search.")
        legint_result: DocketSearchResult = _run_docket_search(target)
        if legint_result and not legint_result.error:
            profile.resolved_from_fragments.append(f"LEGINT:DocketSearch:{target}")
            for record in legint_result.records:
                # Add to graph
                record_id = f"docket:{record.docket_number}"
                graph.add_node(id=record_id, type="CourtDocket", label=record.case_name, properties=record.model_dump())
                graph.add_edge(entity_id, record_id, "NAMED_IN")
                # Add to Pattern of Life
                try:
                    event_time = datetime.strptime(record.date_filed, "%Y-%m-%d")
                    pol_events.append(PatternOfLifeEvent(
                        timestamp=event_time,
                        event_type="LEGINT",
                        summary=f"Named in court docket: {record.case_name}",
                        source_data=record.model_dump(),
                    ))
                except ValueError:
                    logger.warning(f"Could not parse LEGINT date: {record.date_filed}")

        # E) Aviation Intelligence (AVINT) - This is tricky, as it needs a callsign
        # In a real system, we'd get the callsign from another source (e.g., social media).
        # For now, we'll skip if the target isn't an obvious callsign.
        if 2 < len(target) < 8 and target.isalnum(): # Basic callsign check
            logger.info(f"Target '{target}' might be a callsign. Running AVINT.")
            avint_result: AVINTResult = _run_avint_scan(target)
            if avint_result and not avint_result.error:
                 profile.resolved_from_fragments.append(f"AVINT:Callsign:{target}")
                 for flight in avint_result.flights:
                     if flight.latitude and flight.longitude:
                         loc = PhysicalLocation(name=f"Flight {flight.callsign}", address="In-Flight", latitude=flight.latitude, longitude=flight.longitude)
                         profile.linked_physical_locations.append(loc)
                     # Add to Pattern of Life
                     event_time = datetime.fromtimestamp(flight.last_seen)
                     pol_events.append(PatternOfLifeEvent(
                        timestamp=event_time,
                        event_type="AVINT",
                        summary=f"Flight {flight.callsign} detected from {flight.origin_country}",
                        source_data=flight.model_dump(),
                        location=loc
                     ))
        
    except Exception as e:
        logger.error(f"Error during data collection: {e}")
        # Continue with whatever we have
        
    return profile, pol_events


def _build_pattern_of_life(
    pol_events: List[PatternOfLifeEvent], ai_core: AICore
) -> Optional[PatternOfLife]:
    """
    Step 4: Sorts temporal events and uses AI to summarize the Pattern of Life.
    """
    if not pol_events:
        return None
    
    logger.info(f"Building Pattern of Life from {len(pol_events)} events.")
    # Sort events chronologically
    pol_events.sort(key=lambda x: x.timestamp)
    
    # Use AI to summarize the pattern
    event_summaries = "\n".join(
        [f"- {e.timestamp.date()}: [{e.event_type}] {e.summary}" for e in pol_events]
    )
    
    prompt = f"""
    Analyze the following chronological events for a target and produce a concise, 
    executive-level summary of their "Pattern of Life." 
    Focus on routines, anomalies, and key activities.

    Events:
    {event_summaries}

    Summary:
    """
    
    ai_summary = ai_core.generate_text(prompt, max_tokens=200)
    
    return PatternOfLife(
        total_events=len(pol_events),
        events=pol_events,
        ai_summary=ai_summary.strip(),
    )


def _generate_predictions(
    profile: MasterEntityProfile, pol: Optional[PatternOfLife], graph: GraphDatabase, ai_core: AICore
) -> List[CognitivePrediction]:
    """
    Step 5: Use AI to move from descriptive to predictive and prescriptive intelligence.
    """
    logger.info("Generating predictive and cognitive models...")
    
    # Create a rich context from all fused data
    context = f"""
    --- Master Entity Profile ---
    {profile.model_dump_json(indent=2)}

    --- Pattern of Life ---
    {pol.model_dump_json(indent=2) if pol else "No temporal data available."}

    --- Knowledge Graph Summary ---
    {json.dumps(graph.get_graph_summary(), indent=2)}
    """
    
    prompt = f"""
    You are a senior intelligence analyst. Based *only* on the fused data report below,
    generate 2-3 **predictive** or **prescriptive** insights.
    -   **Predictive**: What is likely to happen next? Why?
    -   **Prescriptive**: What is the next logical intelligence-gathering step?

    Format your response as a JSON list of objects, each matching this structure:
    {{
      "prediction_text": "The subject's next likely action is...",
      "confidence": 0.75,
      "justification": "This is based on the correlation between AVINT data and LEGINT filings.",
      "tactic": "Predictive"
    }}

    --- FUSED DATA REPORT ---
    {context}
    
    JSON Output:
    """
    
    try:
        response_text = ai_core.generate_text(prompt, max_tokens=1024)
        # Clean the response to ensure it's valid JSON
        json_str = response_text.strip().replace("```json", "").replace("```", "")
        predictions_data = json.loads(json_str)
        
        return [CognitivePrediction(**p) for p in predictions_data]
    
    except Exception as e:
        logger.error(f"Failed to generate or parse AI predictions: {e}")
        logger.error(f"Raw AI response: {response_text}")
        return [
            CognitivePrediction(
                prediction_text="Failed to generate AI predictions due to parsing error.",
                confidence=1.0,
                justification=str(e),
                tactic="Error"
            )
        ]


# --- Main Orchestrator Function ---

def _run_fusion_analysis(target: str) -> DataFusionResult:
    """
    The main orchestrator that runs the full 4D fusion pipeline.
    """
    logger.info(f"Running 4D Fusion Analysis on target: {target}")
    
    try:
        # Initialize core components
        graph = GraphDatabase()
        ai_core = AICore()
        
        # 1. Collect, Resolve, and find Temporal Events
        profile, pol_events = _collect_and_resolve(target, graph, ai_core)
        
        # 2. Build Pattern of Life from events
        pol = _build_pattern_of_life(pol_events, ai_core)
        
        # 3. Generate Predictions based on all available data
        predictions = _generate_predictions(profile, pol, graph, ai_core)
        
        # 4. Assemble the final report
        return DataFusionResult(
            target_identifier=target,
            master_entity_profile=profile,
            pattern_of_life=pol,
            predictions=predictions,
        )

    except Exception as e:
        logger.error(f"Fatal error in fusion analysis pipeline: {e}", exc_info=True)
        return DataFusionResult(target_identifier=target, error=str(e))


@app.command(
    "run",
    help="Run the fusion engine on a target identifier (name, username, IP, etc.)",
)
def fusion_run(
    target: str = typer.Argument(
        ...,
        help="The target identifier to fuse (e.g., 'John Doe', '1.2.3.4', 'user@example.com').",
    ),
):
    """
    Runs the 4D Fusion Analysis.
    """
    result = _run_fusion_analysis(target)

    if result.error:
        print(f"Error: {result.error}")
        raise typer.Exit(code=1)

    print(f"--- 4D Fusion Analysis Report for: {target} ---")

    if result.master_entity_profile:
        print(f"\n--- Master Entity Profile ({result.master_entity_profile.entity_id}) ---")
        print(f"  Primary Name: {result.master_entity_profile.primary_name}")
        if result.master_entity_profile.aliases:
            print(f"  Aliases: {', '.join(result.master_entity_profile.aliases)}")
        
        if result.master_entity_profile.linked_cyber_indicators:
            print("\n  Linked Cyber Indicators:")
            for indicator in result.master_entity_profile.linked_cyber_indicators:
                print(f"    - {indicator}")
        
        if result.master_entity_profile.linked_physical_locations:
            print("\n  Linked Physical Locations:")
            for loc in result.master_entity_profile.linked_physical_locations:
                print(f"    - {loc.name} ({loc.address})")

        if result.master_entity_profile.linked_social_profiles:
            print("\n  Linked Social Profiles:")
            for prof in result.master_entity_profile.linked_social_profiles:
                print(f"    - {prof.name}: {prof.url}")

        print("\n  Resolved From Fragments:")
        for frag in result.master_entity_profile.resolved_from_fragments:
            print(f"    - {frag}")

    if result.pattern_of_life:
        print("\n--- Pattern of Life (4D) ---")
        print(f"  AI Summary: {result.pattern_of_life.ai_summary}")
        print("\n  Key Events:")
        for event in result.pattern_of_life.events:
            print(f"    - [{event.timestamp}] [{event.event_type}] {event.summary}")

    if result.predictions:
        print("\n--- Predictive & Cognitive Modeling ---")
        for pred in result.predictions:
            print(f"  - Prediction: {pred.prediction_text}")
            print(f"    Confidence: {pred.confidence * 100}%")
            print(f"    Justification: {pred.justification}")
            print(f"    Tactic: {pred.tactic}\n")


if __name__ == "__main__":
    app()