"""
Module for Sentiment Time Series Analysis.

Extends core and social to track a target's or a topic's sentiment
and emotional tone over time. It uses anomaly detection to flag
statistically significant shifts that correlate with real-world events.
"""

import typer
import logging
from typing import List, Optional, Dict, Any
import json
import statistics
import pandas as pd

from .schemas import (
    SentimentTimeSeriesResult,
    SentimentDataPoint,
    SentimentAnomaly,
)
from .gemini_client import GeminiClient
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .project_manager import resolve_target

logger = logging.getLogger(__name__)
gemini_client = GeminiClient()
sentiment_time_series_app = typer.Typer()


def detect_sentiment_anomalies(
    time_series: List[SentimentDataPoint],
) -> List[SentimentAnomaly]:
    """
    Performs anomaly detection on a sentiment time series.

    Uses a simple moving average and standard deviation (Bollinger Bands)
    to detect statistically significant shifts.

    Args:
        time_series (List[SentimentDataPoint]): A list of sentiment data points,
                                                assumed to be sorted by timestamp.

    Returns:
        List[SentimentAnomaly]: A list of detected anomalies.
    """
    anomalies = []
    if len(time_series) < 5:  # Not enough data for anomaly detection
        return anomalies

    try:
        df = pd.DataFrame([dp.model_dump() for dp in time_series])
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.set_index("timestamp").sort_index()

        # Calculate 5-period moving average and standard deviation
        window = 5
        df["moving_avg"] = df["sentiment_score"].rolling(window=window).mean()
        df["moving_std"] = df["sentiment_score"].rolling(window=window).std()

        # Define anomaly boundaries (2 standard deviations)
        df["upper_band"] = df["moving_avg"] + (df["moving_std"] * 2)
        df["lower_band"] = df["moving_avg"] - (df["moving_std"] * 2)

        # Find anomalies
        df_anomalies = df[
            (df["sentiment_score"] > df["upper_band"])
            | (df["sentiment_score"] < df["lower_band"])
        ]

        for index, row in df_anomalies.iterrows():
            if pd.isna(row["moving_avg"]):
                continue

            direction = (
                "Positive"
                if row["sentiment_score"] > row["moving_avg"]
                else "Negative"
            )
            magnitude = abs(row["sentiment_score"] - row["moving_avg"])
            anomalies.append(
                SentimentAnomaly(
                    timestamp=index.isoformat(),
                    document_hint=row["document_hint"],
                    shift_direction=direction,
                    shift_magnitude=round(magnitude, 3),
                    message=f"Sentiment score {row['sentiment_score']:.3f} was "
                            f"{direction.lower()} anomaly "
                            f"(outside band: {row['lower_band']:.3f} - {row['upper_band']:.3f})."
                )
            )
        return anomalies

    except Exception as e:
        logger.error(f"Error during anomaly detection: {e}")
        return [SentimentAnomaly(timestamp="N/A", message=f"Analysis failed: {e}")]


def run_sentiment_time_series(
    target: str, documents: List[Dict[str, str]]
) -> SentimentTimeSeriesResult:
    """
    Uses an LLM to perform sentiment analysis on a list of time-stamped documents.

    Args:
        target (str): The target or topic being analyzed.
        documents (List[Dict[str, str]]): A list of dictionaries, each with
                                           "timestamp" and "content" keys.

    Returns:
        SentimentTimeSeriesResult: A Pydantic model with the time series and anomalies.
    """
    logger.info(f"Running sentiment time series for target: {target}")

    # For simplicity, we process one by one. In a real app, you'd batch this.
    time_series: List[SentimentDataPoint] = []
    overall_scores = []
    overall_errors = 0

    for doc in documents:
        content = doc.get("content", "")
        timestamp = doc.get("timestamp", "UNKNOWN")
        hint = content[:75] + "..." if len(content) > 75 else content

        if not content:
            continue

        prompt = f"""
You are a sentiment analysis AI.
Analyze the sentiment of the following text *regarding the target: "{target}"*.

Instructions:
1.  Read the text and determine the prevailing sentiment (positive, negative, neutral).
2.  Assign a sentiment score from -1.0 (extremely negative) to 1.0 (extremely positive).
3.  Assign an emotional tone (e.g., "Anger", "Joy", "Fear", "Neutral", "Optimistic").
4.  Return *only* a JSON object with "sentiment_score" (float) and "emotional_tone" (str).

Text:
"{content}"
"""

        llm_response = gemini_client.generate_response(prompt)
        if not llm_response:
            logger.warning(f"LLM call for sentiment on doc '{hint}' returned empty.")
            overall_errors += 1
            continue

        try:
            response_json = json.loads(llm_response)
            score = float(response_json.get("sentiment_score", 0.0))
            time_series.append(
                SentimentDataPoint(
                    timestamp=timestamp,
                    sentiment_score=score,
                    emotional_tone=response_json.get("emotional_tone", "Unknown"),
                    document_hint=hint,
                )
            )
            overall_scores.append(score)
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            logger.error(f"Failed to parse LLM sentiment response: {e}")
            logger.debug(f"Raw LLM response: {llm_response}")
            overall_errors += 1

    if not time_series:
        return SentimentTimeSeriesResult(
            target=target, error="No documents could be analyzed."
        )

    # Sort by timestamp before anomaly detection
    time_series.sort(
        key=lambda x: x.timestamp if x.timestamp != "UNKNOWN" else "ZZZZ"
    )

    # Detect anomalies
    anomalies = detect_sentiment_anomalies(time_series)

    return SentimentTimeSeriesResult(
        target=target,
        time_series=time_series,
        anomalies=anomalies,
        overall_average_sentiment=statistics.mean(overall_scores),
        total_documents_analyzed=len(overall_scores),
        total_errors=overall_errors,
    )


@sentiment_time_series_app.command("run")
def run_sentiment_time_series_cli(
    target: Optional[str] = typer.Argument(
        None, help="The target/topic to track. Uses active project if not provided."
    ),
    input_file: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Path to a JSON file containing a list of objects, "
             "each with 'timestamp' and 'content' keys.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Tracks sentiment over time and flags significant shifts.
    """
    target_name = resolve_target(target, required_assets=[])

    try:
        with open(input_file, "r") as f:
            documents = json.load(f)
        if not isinstance(documents, list):
            raise ValueError("Input file must contain a JSON list.")
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/] Input file not found at '{input_file}'")
        raise typer.Exit(code=1)
    except (json.JSONDecodeError, ValueError) as e:
        console.print(f"[bold red]Error:[/] Invalid JSON in file '{input_file}': {e}")
        raise typer.Exit(code=1)

    with console.status(
        f"[bold cyan]Analyzing sentiment time series for {target_name}...[/bold cyan]"
    ):
        results_model = run_sentiment_time_series(target_name, documents)

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_name, module="sentiment_time_series", data=results_dict
    )