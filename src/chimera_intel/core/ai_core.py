import typer
import google.generativeai as genai  # type: ignore
from rich.markdown import Markdown
from typing import List, Optional, Any
import logging
from .utils import console, save_or_print_results
from .config_loader import API_KEYS
from .schemas import SentimentAnalysisResult, SWOTAnalysisResult, AnomalyDetectionResult

# Get a logger instance for this specific file

logger = logging.getLogger(__name__)

# --- AI Model Initializations ---


try:
    from transformers import pipeline  # type: ignore

    sentiment_analyzer = pipeline(
        "sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english"
    )
except (ImportError, OSError):
    sentiment_analyzer = None
    logger.warning(
        "Could not import 'transformers' or load model. Sentiment analysis will be unavailable."
    )
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest  # type: ignore
except ImportError:
    # Explicitly type hint to allow for None value

    IsolationForest: Optional[Any] = None
    np: Optional[Any] = None
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
        raise typer.Exit(code=1)
    try:
        with open(input_file, "r") as f:
            data_str = f.read()
        swot_result = generate_swot_from_data(data_str, api_key)
        if swot_result.error:
            logger.error("SWOT analysis failed: %s", swot_result.error)
        else:
            console.print(Markdown(swot_result.analysis_text))
    except FileNotFoundError:
        logger.error("Input file not found for SWOT analysis: %s", input_file)
    except Exception as e:
        logger.error("Error reading or processing file for SWOT analysis: %s", e)


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
