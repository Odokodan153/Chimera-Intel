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
import logging
import asyncio
from typing import Optional, List, Tuple
from .schemas import (
    DataFusionResult,
    MasterEntityProfile,
    PatternOfLife,
    PatternOfLifeEvent,
    CognitivePrediction,
    PhysicalLocation,
    SocialProfile,
    FootprintResult,
    SocialOSINTResult,
    DocketSearchResult,
    AVINTResult,
    DarkWebScanResult,
)
from .logger_config import get_logger
from datetime import datetime
from .graph_db import graph_db_instance, GraphDB
from .gemini_client import GeminiClient
from .config_loader import API_KEYS
try:
    from .footprint import gather_footprint_data
    from .social_osint import search_profiles as search_social_profiles
    from .legint import search_dockets
    from .avint import get_live_flights
    from .dark_web_osint import search_dark_web_engine
    MODULES_LOADED = True
except ImportError as e:
    MODULES_LOADED = False
    logging.error(f"Failed to import core modules for Fusion: {e}", exc_info=True)


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

def _is_callsign(target: str) -> bool:
    """Basic check for an aviation callsign."""
    return 2 < len(target) < 8 and target.isalnum() and not target.isdigit()


# --- Core Fusion Pipeline Steps ---

async def _collect_and_resolve(
    target: str, graph: GraphDB, ai_client: GeminiClient
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
    entity_id_prompt = f"Generate a unique, stable, machine-readable entity ID for the target: '{target}'. Examples: 'entity-john-doe', 'entity-acme-com'. Return only the ID."
    entity_id = ai_client.generate_response(entity_id_prompt).strip().lower().replace(" ", "-")
    
    profile.entity_id = entity_id
    profile.primary_name = target # Start with the target as the name
    
    graph.add_node(id=entity_id, node_type="MasterEntity", label=target, properties={"query": target})

    if not MODULES_LOADED:
        logger.warning("Core modules not found. Fusion will be limited.")
        return profile, pol_events

    # --- Run Data Collection Modules ---
    tasks_to_run = []
    
    try:
        # A) Footprint (if Domain or IP)
        if _is_domain(target) or _is_ip(target):
            logger.info(f"Target identified as Domain/IP. Scheduling Footprint.")
            tasks_to_run.append(asyncio.create_task(gather_footprint_data(target)))

        # B) Social OSINT (if not IP/Domain)
        if not _is_ip(target):
            logger.info(f"Target not an IP. Scheduling Social OSINT.")
            # social_osint.search_profiles expects a list
            tasks_to_run.append(asyncio.create_task(search_social_profiles([target])))

        # C) Dark Web OSINT (always run)
        logger.info(f"Scheduling Dark Web OSINT.")
        tasks_to_run.append(asyncio.create_task(search_dark_web_engine(target)))
        
        # D) Legal Intelligence (LEGINT) (always run)
        logger.info(f"Scheduling LEGINT docket search.")
        tasks_to_run.append(asyncio.create_task(search_dockets(target)))

        # E) Aviation Intelligence (AVINT) - if it looks like a callsign
        if _is_callsign(target):
            logger.info(f"Target '{target}' might be a callsign. Scheduling AVINT.")
            tasks_to_run.append(asyncio.create_task(get_live_flights(target)))
            
        # --- Run all scheduled tasks ---
        results = await asyncio.gather(*tasks_to_run, return_exceptions=True)

        # --- Process results ---
        for res in results:
            if isinstance(res, Exception):
                logger.error(f"Error during data collection task: {res}")
                continue

            # A) Process Footprint Result
            if isinstance(res, FootprintResult):
                profile.resolved_from_fragments.append(f"CYBINT:Footprint:{target}")
                if res.footprint.dns_records:
                    ips = res.footprint.dns_records.get("A", [])
                    profile.linked_cyber_indicators.extend(ips)
                    for ip in ips:
                        graph.add_node(id=ip, node_type="IPAddress", label=ip)
                        graph.add_edge(entity_id, ip, "RESOLVES_TO")

            # B) Process Social OSINT Result
            elif isinstance(res, SocialOSINTResult):
                profile.resolved_from_fragments.append(f"SOCMINT:Username:{target}")
                if res.profiles:
                    profile.aliases.append(target)
                    for found in res.profiles:
                        soc_profile = SocialProfile(name=found.username, url=found.url, platform=found.platform)
                        profile.linked_social_profiles.append(soc_profile)
                        graph.add_node(id=found.url, node_type="SocialProfile", label=found.username)
                        graph.add_edge(entity_id, found.url, "HAS_PROFILE")

            # C) Process Dark Web OSINT Result
            elif isinstance(res, DarkWebScanResult):
                profile.resolved_from_fragments.append(f"DARKWEB:Query:{target}")
                for found in res.found_results[:5]: # Limit to top 5
                    graph.add_node(id=found.url, node_type="DarkWebPage", label=found.title)
                    graph.add_edge(entity_id, found.url, "MENTIONED_ON")
            
            # D) Process Legal Intelligence (LEGINT) Result
            elif isinstance(res, DocketSearchResult):
                profile.resolved_from_fragments.append(f"LEGINT:DocketSearch:{target}")
                for record in res.records:
                    record_id = f"docket:{record.docket_number}"
                    graph.add_node(id=record_id, node_type="CourtDocket", label=record.case_name, properties=record.model_dump())
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
                    except (ValueError, TypeError):
                        logger.warning(f"Could not parse LEGINT date: {record.date_filed}")

            # E) Process Aviation Intelligence (AVINT) Result
            elif isinstance(res, AVINTResult):
                 profile.resolved_from_fragments.append(f"AVINT:Callsign:{target}")
                 for flight in res.flights:
                     if flight.latitude and flight.longitude:
                         loc = PhysicalLocation(name=f"Flight {flight.callsign}", address="In-Flight", latitude=flight.latitude, longitude=flight.longitude)
                         profile.linked_physical_locations.append(loc)
                     # Add to Pattern of Life (using `last_seen` or `first_seen`)
                     event_time = flight.not_after or datetime.now() # Use most recent time
                     pol_events.append(PatternOfLifeEvent(
                        timestamp=event_time,
                        event_type="AVINT",
                        summary=f"Flight {flight.callsign} detected from {flight.origin_country}",
                        source_data=flight.model_dump(),
                        location=loc if 'loc' in locals() else None
                     ))
        
    except Exception as e:
        logger.error(f"Error during data collection: {e}", exc_info=True)
        # Continue with whatever we have
        
    return profile, pol_events


def _build_pattern_of_life(
    pol_events: List[PatternOfLifeEvent], ai_client: GeminiClient
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
    
    ai_summary = ai_client.generate_response(prompt)
    
    return PatternOfLife(
        total_events=len(pol_events),
        events=pol_events,
        ai_summary=ai_summary.strip(),
    )


def _generate_predictions(
    profile: MasterEntityProfile, pol: Optional[PatternOfLife], graph: GraphDB, ai_client: GeminiClient
) -> List[CognitivePrediction]:
    """
    Step 5: Use AI to move from descriptive to predictive and prescriptive intelligence.
    """
    logger.info("Generating predictive and cognitive models...")
    
    # Create a rich context from all fused data
    context = f"""
    --- Master Entity Profile ---
    {profile.model_dump_json(indent=2, exclude_none=True)}

    --- Pattern of Life ---
    {pol.model_dump_json(indent=2, exclude_none=True) if pol else "No temporal data available."}

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
    {context[:8000]}
    
    Return ONLY the JSON list as a valid JSON object.
    """
    
    response_text = ""
    try:
        response_text = ai_client.generate_response(prompt)
        # Clean the response to ensure it's valid JSON
        json_str = response_text.strip().lstrip("```json").rstrip("```")
        predictions_data = json.loads(json_str)
        
        return [CognitivePrediction.model_validate(p) for p in predictions_data]
    
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

async def _run_fusion_analysis(target: str) -> DataFusionResult:
    """
    The main orchestrator that runs the full 4D fusion pipeline.
    """
    logger.info(f"Running 4D Fusion Analysis on target: {target}")
    
    try:
        # Initialize core components
        graph = graph_db_instance
        
        if not API_KEYS.google_api_key:
             raise ValueError("GOOGLE_API_KEY is not configured, cannot run AI-dependent fusion.")
             
        ai_client = GeminiClient()
        
        # 1. Collect, Resolve, and find Temporal Events
        profile, pol_events = await _collect_and_resolve(target, graph, ai_client)
        
        # 2. Build Pattern of Life from events
        pol = _build_pattern_of_life(pol_events, ai_client)
        
        # 3. Generate Predictions based on all available data
        predictions = _generate_predictions(profile, pol, graph, ai_client)
        
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
    result = asyncio.run(_run_fusion_analysis(target))

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
                print(f"    - {loc.name} ({loc.address or 'In-Flight'})")

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