"""
Module for Entity Resolution and Relationship Extraction.

Normalizes entities (e.g., company names, person names) and extracts
relationships (e.g., subsidiary, colleague) from unstructured text data
to feed into the graph database.
"""

import typer
import logging
from typing import Optional
import json
from .schemas import ResolvedEntity, ExtractedRelationship, ResolutionResult
from .utils import console, save_or_print_results
from .ai_core import generate_swot_from_data  # Reusing for structured JSON extraction
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)


def _resolve_entities_ai(text_blob: str, target_name: str) -> ResolutionResult:
    """
    Uses AI to extract entities and relationships from a blob of text.
    """
    api_key = API_KEYS.google_api_key
    if not api_key:
        return ResolutionResult(entities=[], relationships=[], error="Google API key not found.")

    prompt = f"""
    You are an intelligence analyst tasked with entity resolution and relationship extraction.
    Analyze the following text blob related to the primary target "{target_name}".

    Your goal is to:
    1. Identify all people and companies.
    2. Normalize their names (e.g., "Google, Inc." -> "Google").
    3. Extract explicit relationships between them (e.g., "subsidiary_of", "colleague_of", "family_of", "works_at").

    Text Blob:
    \"\"\"
    {text_blob}
    \"\"\"

    Return your findings as a single, valid JSON object with two keys: "entities" and "relationships".
    - "entities": A list of objects, where each object has "raw_name", "normalized_name", and "entity_type" ("person" or "company").
    - "relationships": A list of objects, where each object has "source_entity" (normalized), "target_entity" (normalized), "relationship_type", and "context" (the quote supporting the finding).

    Example:
    {{
      "entities": [
        {{"raw_name": "Google, Inc.", "normalized_name": "Google", "entity_type": "company"}},
        {{"raw_name": "Sundar Pichai", "normalized_name": "Sundar Pichai", "entity_type": "person"}}
      ],
      "relationships": [
        {{"source_entity": "Sundar Pichai", "target_entity": "Google", "relationship_type": "works_at", "context": "Sundar Pichai, CEO of Google, Inc."}}
      ]
    }}

    Return ONLY the valid JSON object.
    """

    try:
        # Re-use the ai_core function
        ai_result = generate_swot_from_data(prompt, api_key)
        if ai_result.error:
            raise Exception(ai_result.error)

        json_text = ai_result.analysis_text.strip().lstrip("```json").rstrip("```")
        parsed_data = json.loads(json_text)

        entities = [ResolvedEntity.model_validate(e) for e in parsed_data.get("entities", [])]
        relationships = [ExtractedRelationship.model_validate(r) for r in parsed_data.get("relationships", [])]

        return ResolutionResult(entities=entities, relationships=relationships)

    except Exception as e:
        logger.error(f"Failed to run AI entity resolution: {e}")
        return ResolutionResult(entities=[], relationships=[], error=str(e))


# --- CLI Application ---

entity_app = typer.Typer(
    name="entity-resolver",
    help="Normalize entities and extract relationships from text."
)

@entity_app.command("resolve-text")
def resolve_entities_from_text(
    target_name: str = typer.Argument(..., help="The primary target name for context."),
    input_file: str = typer.Option(
        ..., "--input", "-i", help="Path to a .txt file containing the text blob to analyze."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes a text file to extract and normalize entities and their relationships.
    """
    console.print(f"[bold cyan]Resolving entities from '{input_file}'...[/bold cyan]")
    
    try:
        with open(input_file, 'r') as f:
            text_blob = f.read()
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] Input file not found at '{input_file}'.")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Error reading file:[/bold red] {e}")
        raise typer.Exit(code=1)

    if not API_KEYS.google_api_key:
        console.print("[bold red]Error:[/bold red] 'GOOGLE_API_KEY' not found in config. Cannot use AI features.")
        raise typer.Exit(code=1)

    with console.status("[spinner]Running AI analysis..."):
        result = _resolve_entities_ai(text_blob, target_name)

    if result.error:
        console.print(f"[bold red]Error during analysis:[/bold red] {result.error}")
        raise typer.Exit(code=1)

    console.print(f"[green]Successfully extracted {len(result.entities)} entities and {len(result.relationships)} relationships.[/green]")
    
    save_or_print_results(result.model_dump(), output_file)