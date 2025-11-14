"""
Module for Event Modeling.

Automatically identifies and graphs all related entities, events,
and timestamps from a collection of raw data to reconstruct a
complete, verifiable sequence of events (e.g., an incident timeline).
"""

import typer
import logging
from typing import List, Optional
import json
from .schemas import (
    EventModelingResult,
    Event,
    EventEntity,
)
from .gemini_client import GeminiClient
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .project_manager import resolve_target

logger = logging.getLogger(__name__)
gemini_client = GeminiClient()
event_modeling_app = typer.Typer()


def run_event_modeling(
    target: str, raw_data_reports: List[str]
) -> EventModelingResult:
    """
    Uses an LLM to extract a sequence of events from raw text reports.

    Args:
        target (str): The primary target/subject of the event timeline.
        raw_data_reports (List[str]): A list of strings, where each string
                                      is a raw data report (e.g., news article,
                                      log entry, field report).

    Returns:
        EventModelingResult: A Pydantic model with the structured event timeline.
    """
    logger.info(f"Running event modeling for target: {target}")

    # Combine reports into a single block for the prompt
    combined_reports = "\n--- END OF REPORT ---\n".join(raw_data_reports)

    prompt = f"""
You are an incident investigator and timeline reconstruction AI.
Your task is to analyze a collection of raw data reports and extract a
chronological sequence of events related to the primary target.

Primary Target: "{target}"

Raw Data Reports:
{combined_reports}

Instructions:
1.  Read all reports and identify key events, entities involved, and timestamps.
2.  Normalize all timestamps to 'YYYY-MM-DDTHH:MM:SS' format if possible.
    If only a date is given, use T00:00:00. If no time is given, use 'UNKNOWN'.
3.  For each event, list the entities involved (people, organizations, locations, assets).
4.  Sort the events chronologically.
5.  Return your answer *strictly* as a JSON object with a single key: "timeline".
    The value of "timeline" should be a list of objects, where each object has:
    - "timestamp" (str): The normalized timestamp.
    - "event_description" (str): A concise description of what happened.
    - "entities" (list): A list of objects, each with "name" (str) and "type" (str).
    - "source_report_hint" (str): A brief hint or quote from the report that
      supports this event.

Example of the "timeline" list structure:
[
    {{
        "timestamp": "2023-10-27T09:15:00",
        "event_description": "Unauthorized access detected on 'server-db-01'.",
        "entities": [
            {{"name": "server-db-01", "type": "asset"}},
            {{"name": "User 'admin'", "type": "person"}}
        ],
        "source_report_hint": "Log file shows login failure followed by success for 'admin' at 9:15"
    }},
    {{
        "timestamp": "2023-10-27T09:30:00",
        "event_description": "Data exfiltration observed from 'server-db-01' to IP 123.45.67.89.",
        "entities": [
            {{"name": "server-db-01", "type": "asset"}},
            {{"name": "123.45.67.89", "type": "indicator"}}
        ],
        "source_report_hint": "Network traffic analysis shows large outbound transfer to 123.45.67.89"
    }}
]
"""

    llm_response = gemini_client.generate_response(prompt)
    if not llm_response:
        error_msg = "LLM call for event modeling returned an empty response."
        logger.error(error_msg)
        return EventModelingResult(target=target, error=error_msg)

    try:
        response_json = json.loads(llm_response)
        timeline_data = response_json.get("timeline", [])

        # Parse the JSON data into Pydantic models
        timeline = [
            Event(
                timestamp=evt.get("timestamp", "UNKNOWN"),
                event_description=evt.get("event_description", "No description"),
                entities=[
                    EventEntity(
                        name=ent.get("name", "Unknown"), type=ent.get("type", "Unknown")
                    )
                    for ent in evt.get("entities", [])
                ],
                source_report_hint=evt.get("source_report_hint", "N/A"),
            )
            for evt in timeline_data
        ]

        # Sort by timestamp
        timeline.sort(
            key=lambda x: x.timestamp
            if x.timestamp != "UNKNOWN"
            else "ZZZZ"
        )

        return EventModelingResult(
            target=target,
            timeline=timeline,
            total_events=len(timeline),
        )
    except (json.JSONDecodeError, TypeError, AttributeError) as e:
        logger.error(f"Failed to parse LLM JSON response for event modeling: {e}")
        logger.debug(f"Raw LLM response: {llm_response}")
        return EventModelingResult(
            target=target,
            error="Event modeling failed due to malformed LLM response.",
        )


@event_modeling_app.command("run")
def run_event_modeling_cli(
    target: Optional[str] = typer.Argument(
        None,
        help="The primary target/subject. Uses active project if not provided.",
    ),
    input_dir: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Path to a directory containing raw data .txt files to be modeled.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save timeline results to a JSON file."
    ),
):
    """
    Reconstructs a sequence of events from a collection of raw data.
    """
    import os

    target_name = resolve_target(target, required_assets=[])

    if not os.path.isdir(input_dir):
        console.print(f"[bold red]Error:[/] Input path '{input_dir}' is not a valid directory.")
        raise typer.Exit(code=1)

    raw_reports: List[str] = []
    try:
        for filename in os.listdir(input_dir):
            if filename.endswith(".txt"):
                filepath = os.path.join(input_dir, filename)
                with open(filepath, "r", encoding="utf-8") as f:
                    raw_reports.append(f.read())
    except Exception as e:
        console.print(f"[bold red]Error reading files from '{input_dir}': {e}")
        raise typer.Exit(code=1)

    if not raw_reports:
        console.print(f"[bold yellow]Warning:[/] No .txt files found in '{input_dir}'.")
        raise typer.Exit()

    console.print(f"Found {len(raw_reports)} reports to analyze.")

    with console.status(
        f"[bold cyan]Reconstructing event timeline for {target_name}...[/bold cyan]"
    ):
        results_model = run_event_modeling(target_name, raw_reports)

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=target_name, module="event_modeling", data=results_dict)