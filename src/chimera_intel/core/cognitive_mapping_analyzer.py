"""
Module for Cognitive Mapping Analysis.

Analyzes the public communications of key individuals to model
their decision-making biases, values, and mental models.
"""

import typer
import logging
import json
from typing import Optional, List
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .narrative_analyzer import track_narrative_gnews  
from .config_loader import API_KEYS
from .gemini_client import GeminiClient
from .schemas import CognitiveMapResult, MentalModelVector
logger = logging.getLogger(__name__)



# --- Module Internals ---

cognitive_mapping_app = typer.Typer()
gemini_client = GeminiClient()


def generate_cognitive_map(person_name: str) -> CognitiveMapResult:
    """
    (REAL) Generates a cognitive map by analyzing public statements.

    Args:
        person_name (str): The full name of the key individual to analyze.

    Returns:
        CognitiveMapResult: A Pydantic model containing the synthesized profile.
    """
    logger.info(f"Generating cognitive map for {person_name}")
    
    # 1. Gather public communications (speeches, interviews)
    # (REAL) Use the actual function from narrative_analyzer
    if not API_KEYS.gnews_api_key:
        return CognitiveMapResult(
            person_name=person_name,
            error="GNews API key not configured. Cannot gather communications."
        )
        
    public_communications = track_narrative_gnews(person_name, limit=15)

    if not public_communications:
        return CognitiveMapResult(
            person_name=person_name,
            error="No public communications found for this individual via GNews.",
        )

    # 2. Synthesize communications into a single text block for AI analysis
    full_text = " ".join(
        [f"{item.get('title', '')}. {item.get('content', '')}" for item in public_communications]
    )
    
    # 3. Use AI core to build the cognitive model with a structured JSON prompt
    api_key = API_KEYS.google_api_key
    if not api_key:
        return CognitiveMapResult(
            person_name=person_name, error="Google API key not configured."
        )

    prompt = f"""
    As an intelligence psychologist, analyze the following public statements (speeches, interviews, articles) from or about '{person_name}'.
    Based on the language, recurring themes, and expressed opinions, create a formal cognitive map.

    **Source Material:**
    {full_text[:8000]}

    **Instructions:**
    Return your analysis as a single JSON object with the following keys:
    1.  "cognitive_model_summary": (string) A 2-3 paragraph summary of their overall decision-making framework and worldview.
    2.  "predictive_assessment": (string) A brief, predictive assessment of how they might react to a sudden, unexpected market disruption or crisis.
    3.  "key_vectors": (array of objects) An array of their core mental models. Each object must have:
        - "vector_type": (string) The type of vector (e.g., "Core Value", "Decision-Making Bias", "Mental Model", "Cognitive Trigger").
        - "description": (string) The specific value or bias (e.g., "Prioritizes rapid innovation over stability", "Shows signs of Optimism Bias").
        - "evidence_snippet": (string) A direct quote or 1-sentence summary from the source material that supports this vector.

    Example for "key_vectors":
    [
        {{"vector_type": "Core Value", "description": "Believes in aggressive market expansion", "evidence_snippet": "Our goal is to be number one in every market we enter."}},
        {{"vector_type": "Decision-Making Bias", "description": "Loss Aversion", "evidence_snippet": "We must protect our current market share at all costs."}}
    ]

    Return ONLY the valid JSON object and nothing else.
    """

    llm_response = gemini_client.generate_response(prompt)
    
    if not llm_response:
        logger.error(f"AI analysis for {person_name} returned an empty response.")
        return CognitiveMapResult(
            person_name=person_name,
            error="AI analysis failed (empty response)."
        )

    # 4. Parse the structured JSON response
    try:
        json_text = llm_response.strip().lstrip("```json").rstrip("```")
        data = json.loads(json_text)
        
        summary = data.get("cognitive_model_summary")
        prediction = data.get("predictive_assessment")
        
        vectors_data = data.get("key_vectors", [])
        key_vectors: List[MentalModelVector] = []
        for vec in vectors_data:
            key_vectors.append(
                MentalModelVector(
                    vector_type=vec.get("vector_type", "Unknown"),
                    description=vec.get("description", "N/A"),
                    evidence_snippet=vec.get("evidence_snippet")
                )
            )
        
        if not key_vectors and not summary:
             raise ValueError("AI response was valid JSON but missing required fields.")

        return CognitiveMapResult(
            person_name=person_name,
            cognitive_model_summary=summary,
            key_vectors=key_vectors,
            predictive_assessment=prediction,
        )

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse AI JSON response for {person_name}: {e}")
        logger.debug(f"Raw LLM response: {llm_response}")
        return CognitiveMapResult(
            person_name=person_name,
            error=f"AI response was not valid JSON. See logs for details."
        )
    except Exception as e:
        logger.error(f"An unexpected error occurred during profile generation for {person_name}: {e}")
        return CognitiveMapResult(
            person_name=person_name,
            error=str(e)
        )


@cognitive_mapping_app.command("run")
def run_cognitive_mapping(
    person_name: str = typer.Argument(
        ..., help="The full name of the individual to analyze."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes public communications to build a cognitive map of a key individual.
    """
    with console.status(
        f"[bold cyan]Generating cognitive map for {person_name}...[/bold cyan]"
    ):
        results_model = generate_cognitive_map(person_name)
    
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    
    if not results_model.error:
        save_scan_to_db(
            target=person_name, module="cognitive_mapping", data=results_dict
        )
    else:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")