"""
Module for Threat Actor Intelligence.

Handles the gathering of intelligence on known threat actors, their TTPs,
and their infrastructure from external sources. It also manages the local
threat actor library within the Chimera Intel database.
"""

import logging
from typing import Optional, Dict, Any, List

import typer
import asyncio
from .config_loader import API_KEYS
from .database import save_scan_to_db
from .http_client import sync_client
from .schemas import TTP, ThreatActor, ThreatActorIntelResult
from .utils import console, save_or_print_results

logger = logging.getLogger(__name__)

async def search_threat_actors(indicator: str) -> List[ThreatActor]:
    """
    Searches for threat actors associated with a given indicator.
    It runs the synchronous OTX profile function in a separate thread.
    """
    # Use to_thread to run the synchronous network call without blocking the event loop
    profile_result = await asyncio.to_thread(get_threat_actor_profile, indicator)

    # get_threat_actor_profile returns ThreatActorIntelResult which holds an optional actor.
    if profile_result.actor:
        return [profile_result.actor] # Return a list containing the single found actor

    return [] # Return an empty list if no actor is found


def get_threat_actor_profile(group_name: str) -> ThreatActorIntelResult:
    """
    Fetches a profile of a threat actor group by searching for related "Pulses"
    in the AlienVault OTX API.

    Args:
        group_name (str): The name of the threat actor group (e.g., "APT28").

    Returns:
        ThreatActorIntelResult: A Pydantic model containing the actor's profile.
    """
    api_key = API_KEYS.otx_api_key
    if not api_key:
        return ThreatActorIntelResult(
            error="AlienVault OTX API key (OTX_API_KEY) is not configured."
        )
    logger.info(f"Searching OTX for threat actor profile: {group_name}")

    # Use the OTX search endpoint to find Pulses tagged with the actor's name

    url = "https://otx.alienvault.com/api/v1/search/pulses"
    headers = {"X-OTX-API-KEY": api_key}
    params: Dict[str, Any] = {
        "q": group_name,
        "sort": "-modified",
        "limit": 10,
    }  # Get 10 most recent pulses

    try:
        response = sync_client.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        if not data.get("results"):
            return ThreatActorIntelResult(
                error=f"No intelligence pulses found for '{group_name}' in OTX."
            )
        # --- Synthesize a Profile from Multiple Pulses ---
        # We will aggregate data from all found pulses to build one profile.

        aliases = set()
        targeted_industries = set()
        known_ttps: Dict[str, TTP] = {}  # Use a dict to store unique TTPs
        known_indicators = set()

        industry_keywords = [
            "government",
            "energy",
            "financial",
            "healthcare",
            "defense",
        ]

        for pulse in data.get("results", []):
            for tag in pulse.get("tags", []):
                tag_lower = tag.lower()
                if group_name.lower() in tag_lower:
                    continue  # Skip the primary name itself
                is_industry = any(keyword in tag_lower for keyword in industry_keywords)

                if is_industry:
                    targeted_industries.add(tag.capitalize())
                else:
                    # If it's not the primary name and not an industry, it's likely an alias.

                    aliases.add(tag)
            # Extract TTPs from ATT&CK IDs

            for attack_id in pulse.get("attack_ids", []):
                technique_id = attack_id.get("id")
                if technique_id and technique_id not in known_ttps:
                    known_ttps[technique_id] = TTP(
                        technique_id=technique_id,
                        tactic=attack_id.get("tactic", "Unknown")
                        .replace("-", " ")
                        .title(),
                        description=attack_id.get("name", "No description available."),
                    )
            # Extract indicators

            for indicator in pulse.get("indicators", []):
                indicator_value = indicator.get("indicator")
                if indicator_value:
                    known_indicators.add(indicator_value)
        actor = ThreatActor(
            name=group_name,
            aliases=list(aliases),
            targeted_industries=list(targeted_industries),
            known_ttps=list(known_ttps.values()),
            known_indicators=list(known_indicators)[:50],  # Limit for brevity
        )

        return ThreatActorIntelResult(actor=actor)
    except Exception as e:
        logger.error(f"An error occurred while querying OTX for '{group_name}': {e}")
        return ThreatActorIntelResult(error=f"An API error occurred: {e}")


# --- Typer CLI Application ---


threat_actor_app = typer.Typer()


@threat_actor_app.command("profile")
def run_threat_actor_profile(
    actor_name: str = typer.Argument(
        ..., help="The name of the threat actor (e.g., 'APT28', 'FIN7')."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Gathers and synthesizes an intelligence profile for a known threat actor."""
    with console.status(
        f"[bold cyan]Profiling threat actor '{actor_name}'...[/bold cyan]"
    ):
        results_model = get_threat_actor_profile(actor_name)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=actor_name, module="threat_actor_profile", data=results_dict)
