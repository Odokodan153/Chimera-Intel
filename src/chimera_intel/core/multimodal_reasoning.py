"""
Module for Multimodal Reasoning.

Processes and reasons across different data types simultaneously
(e.g., text, image, audio, geo-location) to find connections.
"""

import typer
import logging
from typing import List, Optional, Dict, Any
import json

from .schemas import (
    MultimodalReasoningResult,
    AnalysisResult,
)
from .gemini_client import GeminiClient
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .project_manager import resolve_target

logger = logging.getLogger(__name__)
gemini_client = GeminiClient()
multimodal_reasoning_app = typer.Typer()


def run_multimodal_reasoning(
    target: str, data_inputs: Dict[str, Any]
) -> MultimodalReasoningResult:
    """
    Uses an LLM to reason across a dictionary of multimodal data inputs.

    Args:
        target (str): The primary target of the analysis.
        data_inputs (Dict[str, Any]): A dictionary where keys are data types
            (e.g., "transcribed_audio", "image_analysis", "geoint_report")
            and values are the corresponding data (e.g., text, object lists, locations).

    Returns:
        MultimodalReasoningResult: A Pydantic model with the findings.
    """
    logger.info(f"Running multimodal reasoning for target: {target}")

    # In a real implementation, this would handle complex inputs,
    # potentially including file paths for models like Gemini Pro Vision.
    # For this example, we'll serialize all inputs to JSON for a text-based prompt.

    try:
        serialized_inputs = json.dumps(data_inputs, indent=2, default=str)
    except Exception as e:
        logger.error(f"Could not serialize multimodal inputs: {e}")
        return MultimodalReasoningResult(
            target=target,
            error=f"Could not serialize input data: {e}",
        )

    prompt = f"""
You are a multimodal intelligence fusion analyst.
Your task is to analyze inputs from different data sources and find connections, patterns,
and insights that would be missed by analyzing each source in isolation.

Target: "{target}"

Data Inputs:
{serialized_inputs}

Instructions:
1.  **Cross-Correlate Entities:** Identify entities (people, places, organizations)
    that appear across different data types. For example, does a name mentioned in
    "transcribed_audio" match a face in "image_analysis"?
2.  **Identify Connections:** Find links between the inputs. Does the location in
    "geoint_report" match a background scene in an "image_analysis"?
3.  **Formulate Insights:** Based on these connections, what new insights or
    hypotheses can be formed about the target's activities or relationships?

Format your response as a JSON object with two keys:
- "cross_correlations": A list of strings describing entities found in multiple data types.
- "fused_insights": A list of strings describing new insights gained from fusing the data.

Example:
{{
    "cross_correlations": [
        "Entity 'John Doe' from 'transcribed_audio' matches 'Person_1' in 'image_analysis: people.jpg'."
    ],
    "fused_insights": [
        "The meeting discussed by 'John Doe' likely took place at the 'Eiffel Tower',
        which is present in both 'geoint_report' and 'image_analysis: scene.jpg'."
    ]
}}
"""

    llm_response = gemini_client.generate_response(prompt)
    if not llm_response:
        error_msg = "LLM call for multimodal reasoning returned an empty response."
        logger.error(error_msg)
        return MultimodalReasoningResult(target=target, error=error_msg)

    try:
        response_json = json.loads(llm_response)
        result = MultimodalReasoningResult(
            target=target,
            cross_correlations=response_json.get("cross_correlations", []),
            fused_insights=response_json.get("fused_insights", []),
        )
        return result
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM JSON response for reasoning: {e}")
        logger.debug(f"Raw LLM response: {llm_response}")
        return MultimodalReasoningResult(
            target=target, error="Reasoning failed due to malformed LLM response."
        )


@multimodal_reasoning_app.command("run")
def run_multimodal_reasoning_cli(
    target: Optional[str] = typer.Argument(
        None, help="The primary target. Uses active project if not provided."
    ),
    input_file: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Path to a JSON file containing the multimodal data inputs.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Processes and reasons across different data types simultaneously.
    """
    target_name = resolve_target(target, required_assets=[])

    try:
        with open(input_file, "r") as f:
            data_inputs = json.load(f)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/] Input file not found at '{input_file}'")
        raise typer.Exit(code=1)
    except json.JSONDecodeError:
        console.print(f"[bold red]Error:[/] Invalid JSON in file '{input_file}'")
        raise typer.Exit(code=1)

    with console.status(
        f"[bold cyan]Running multimodal fusion for {target_name}...[/bold cyan]"
    ):
        results_model = run_multimodal_reasoning(target_name, data_inputs)

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_name, module="multimodal_reasoning", data=results_dict
    )