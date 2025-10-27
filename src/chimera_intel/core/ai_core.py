"""
Core AI functionalities for sentiment analysis, SWOT generation, and anomaly detection.

This module initializes and provides access to various AI models. It uses local
'transformers' for sentiment analysis and zero-shot classification, Google's
Generative AI (Gemini Pro) for SWOT analysis from structured data, and
'scikit-learn' for traffic anomaly detection. Models are loaded lazily and
conditionally to prevent crashes if optional dependencies are not installed.
"""

import typer
import google.generativeai as genai  # type: ignore
from rich.markdown import Markdown
from typing import List, Optional, Any, Dict
import logging
from .utils import console, save_or_print_results
from .config_loader import API_KEYS
from .schemas import (
    SentimentAnalysisResult,
    SWOTAnalysisResult,
    AnomalyDetectionResult
)
from .graph_schemas import GraphEdge, GraphNode, EntityGraphResult,GraphNarrativeResult
from .graph_db import build_and_save_graph
import json
import os

# Get a logger instance for this specific file


logger = logging.getLogger(__name__)

# --- AI Model Initializations ---

# Define variables before the try block


sentiment_analyzer: Optional[Any] = None
classifier: Optional[Any] = None
IsolationForest: Optional[Any] = None
np: Optional[Any] = None

try:
    from transformers import pipeline  # type: ignore

    sentiment_analyzer = pipeline(  # type: ignore
        "sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english"
    )
    classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
except (ImportError, OSError):
    logger.warning(
        "Could not import 'transformers' or load models. AI analysis will be unavailable."
    )
try:
    import numpy
    from sklearn.ensemble import IsolationForest as SklearnIsolationForest  # type: ignore

    # Assign the imported modules/classes to our variables

    np = numpy
    IsolationForest = SklearnIsolationForest
except ImportError:
    logger.warning(
        "Could not import 'scikit-learn' or 'numpy'. Anomaly detection will be unavailable."
    )


def analyze_sentiment(text: str) -> SentimentAnalysisResult:
    """
    Analyzes the sentiment of a given text using a local transformer model.

    Args:
        text (str): The text to analyze.

    Returns:
        SentimentAnalysisResult: A Pydantic model containing the sentiment label, score, or an error.
    """
    if not sentiment_analyzer:
        return SentimentAnalysisResult(
            label="ERROR", score=0.0, error="'transformers' or 'torch' not installed."
        )
    try:
        result = sentiment_analyzer(text)[0]
        return SentimentAnalysisResult(label=result["label"], score=result["score"])
    except Exception as e:
        logger.error("Sentiment analysis failed for text '%s...': %s", text[:50], e)
        return SentimentAnalysisResult(
            label="ERROR", score=0.0, error=f"Sentiment analysis error: {e}"
        )


def classify_text_zero_shot(
    text: str, candidate_labels: List[str]
) -> Optional[Dict[str, Any]]:
    """
    Classifies a given text against a list of candidate labels using a zero-shot model.

    Args:
        text (str): The text to classify.
        candidate_labels (List[str]): The list of labels to classify against.

    Returns:
        Optional[Dict[str, Any]]: A dictionary with labels and scores, or None on error.
    """
    if not classifier:
        logger.warning("Zero-shot classifier not available. Skipping classification.")
        return None
    try:
        # Truncate text to avoid model errors with very long inputs

        return classifier(text[:512], candidate_labels)
    except Exception as e:
        logger.error(
            "Zero-shot classification failed for text '%s...': %s", text[:50], e
        )
        return None


def generate_swot_from_data(json_data_str: str, api_key: str) -> SWOTAnalysisResult:
    """
    Uses a Generative AI model (Gemini Pro) to create a SWOT analysis from OSINT data.

    Args:
        json_data_str (str): A string containing the JSON OSINT data.
        api_key (str): The Google AI API key.

    Returns:
        SWOTAnalysisResult: A Pydantic model containing the markdown-formatted SWOT analysis, or an error.
    """
    if not api_key:
        return SWOTAnalysisResult(
            analysis_text="", error="GOOGLE_API_KEY not found in .env file."
        )
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-pro")
    prompt = f"""Based on the following OSINT data, perform a SWOT analysis.
    Present the output in Markdown format with clear headings for Strengths, Weaknesses, Opportunities, and Threats.
    OSINT Data: {json_data_str}"""
    try:
        response = model.generate_content(prompt)
        return SWOTAnalysisResult(analysis_text=response.text)
    except Exception as e:
        logger.error("Google AI API error during SWOT generation: %s", e)
        return SWOTAnalysisResult(analysis_text="", error=f"Google AI API error: {e}")


def detect_traffic_anomalies(traffic_data: List[float]) -> AnomalyDetectionResult:
    """
    Uses Isolation Forest to detect anomalies in a time series of numerical data.

    Args:
        traffic_data (List[float]): A list of numbers (e.g., monthly website visits).

    Returns:
        AnomalyDetectionResult: A Pydantic model containing the original data, detected anomalies, or an error.
    """
    if not IsolationForest or not np:
        return AnomalyDetectionResult(
            data_points=traffic_data,
            detected_anomalies=[],
            error="'scikit-learn' or 'numpy' not installed.",
        )
    
    # --- FIX: Handle empty list gracefully ---
    if not traffic_data:
        return AnomalyDetectionResult(
            data_points=[],
            detected_anomalies=[]
        )
    # --- End Fix ---
    
    if not all(isinstance(x, (int, float)) for x in traffic_data):
        return AnomalyDetectionResult(
            data_points=traffic_data,
            detected_anomalies=[],
            error="Invalid input. Please provide a list of numbers.",
        )
    try:
        data_array = np.array(traffic_data).reshape(-1, 1)
        clf = IsolationForest(contamination="auto", random_state=42)
        predictions = clf.fit_predict(data_array)
        anomalies = [
            traffic_data[i] for i, pred in enumerate(predictions) if pred == -1
        ]
        return AnomalyDetectionResult(
            data_points=traffic_data, detected_anomalies=anomalies
        )
    except Exception as e:
        logger.error("Anomaly detection failed: %s", e)
        return AnomalyDetectionResult(
            data_points=traffic_data,
            detected_anomalies=[],
            error=f"Anomaly detection error: {e}",
        )


# --- Typer CLI Application ---


ai_app = typer.Typer()


@ai_app.command("sentiment")
def run_sentiment_analysis(text: str):
    """
    Analyzes the sentiment of a piece of text.

    Args:
        text (str): The input text for sentiment analysis.
    """
    logger.info("Running sentiment analysis.")
    result = analyze_sentiment(text)
    save_or_print_results(result.model_dump(), None)


@ai_app.command("swot")
def run_swot_analysis(input_file: str):
    """
    Generates a SWOT analysis from a JSON data file.

    Args:
        input_file (str): The path to the JSON file containing OSINT data.
    """
    logger.info("Generating SWOT analysis from file: %s", input_file)
    api_key = API_KEYS.google_api_key
    if not api_key:
        logger.error(
            "Google API key not found. Please set GOOGLE_API_KEY in your .env file."
        )
        console.print("Google API key not found")
        raise typer.Exit(code=1)
    try:
        with open(input_file, "r") as f:
            data_str = f.read()
        json.loads(data_str)  # Validate JSON
        swot_result = generate_swot_from_data(data_str, api_key)
        if swot_result.error:
            logger.error("SWOT analysis failed: %s", swot_result.error)
            raise typer.Exit(code=1)
        else:
            console.print(Markdown(swot_result.analysis_text))
    except FileNotFoundError:
        logger.error("Input file not found for SWOT analysis: %s", input_file)
        raise typer.Exit(code=1)
    except json.JSONDecodeError:
        logger.error("Invalid JSON in file '%s'", input_file)
        console.print("Invalid JSON")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error("Error reading or processing file for SWOT analysis: %s", e)
        raise typer.Exit(code=1)


@ai_app.command("anomaly")
def run_anomaly_detection(data_points: str):
    """
    Detects anomalies in a numerical dataset (e.g., '100,110,250,90').

    Args:
        data_points (str): A comma-separated string of numbers.
    """
    logger.info("Running anomaly detection.")
    try:
        numeric_data = [float(p.strip()) for p in data_points.split(",") if p.strip()]
        if not numeric_data:
            raise ValueError("No valid numbers provided.")
        result = detect_traffic_anomalies(numeric_data)
        save_or_print_results(result.model_dump(), None)
    except ValueError as e:
        logger.error(
            "Invalid data points for anomaly detection: %s. Error: %s", data_points, e
        )
        console.print("Invalid data points")


def generate_narrative_from_graph(target: str, api_key: str) -> GraphNarrativeResult:
    """
    Uses a Generative AI model to create a narrative from an entity graph.

    Args:
        target (str): The target for which to generate the narrative.
        api_key (str): The Google AI API key.

    Returns:
        GraphNarrativeResult: A Pydantic model containing the AI-generated narrative.
    """
    if not os.path.exists(target):
        return GraphNarrativeResult(narrative_text="", error="DB error")
    try:
        with open(target, "r") as f:
            data = json.load(f)
        output_path = f"{target.replace('.json', '')}_graph.html"
        build_and_save_graph(data, output_path)

        nodes = []
        edges = []
        target_node_id = data.get("domain") or data.get("company", "Unknown Target")
        nodes.append(
            GraphNode(
                id=target_node_id,
                label=target_node_id,
                node_type="Main Target",
                properties={},
            )
        )

        footprint_data = data.get("footprint", {})
        for sub_item in footprint_data.get("subdomains", {}).get("results", []):
            subdomain = sub_item.get("domain")
            if subdomain:
                nodes.append(
                    GraphNode(
                        id=subdomain,
                        label=subdomain,
                        node_type="Subdomain",
                        properties={},
                    )
                )
                edges.append(
                    GraphEdge(
                        source=target_node_id,
                        target=subdomain,
                        label="has_subdomain",
                        properties={},
                    )
                )
        for ip in footprint_data.get("dns_records", {}).get("A", []):
            if "Error" not in str(ip):
                nodes.append(
                    GraphNode(id=ip, label=ip, node_type="IP Address", properties={})
                )
                edges.append(
                    GraphEdge(
                        source=target_node_id,
                        target=ip,
                        label="resolves_to",
                        properties={},
                    )
                )
        web_data = data.get("web_analysis", {})
        for tech_item in web_data.get("tech_stack", {}).get("results", []):
            tech = tech_item.get("technology")
            if tech:
                nodes.append(
                    GraphNode(
                        id=tech, label=tech, node_type="Technology", properties={}
                    )
                )
                edges.append(
                    GraphEdge(
                        source=target_node_id,
                        target=tech,
                        label="uses_tech",
                        properties={},
                    )
                )
        # Corrected from GraphResult to EntityGraphResult

        graph_result = EntityGraphResult(
            nodes=nodes,
            edges=edges,
            target=target,
            total_nodes=len(nodes),
            total_edges=len(edges),
        )
        if hasattr(graph_result, "error") and graph_result.error:
            return GraphNarrativeResult(narrative_text="", error=graph_result.error)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return GraphNarrativeResult(narrative_text="", error=str(e))
    prompt_data = {
        "nodes": [node.model_dump() for node in graph_result.nodes],
        "edges": [edge.model_dump() for edge in graph_result.edges],
    }

    swot_result = generate_swot_from_data(
        f"Analyze the following entity graph and provide a brief intelligence summary:\n{json.dumps(prompt_data, indent=2)}",
        api_key,
    )

    return GraphNarrativeResult(
        narrative_text=swot_result.analysis_text, error=swot_result.error
    )