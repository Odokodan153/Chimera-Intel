"""
Module for Cultural Sentiment Analysis.

Assesses sentiment (brand, employee, public) with cultural context.
Combines raw sentiment scores with cultural profiles to provide
a more accurate, region-specific interpretation.
"""

import typer
import logging
from typing import Optional
from textblob import TextBlob
from .schemas import CulturalSentimentResult
from .utils import console, save_or_print_results
from .database import save_scan_to_db
from .cultural_intelligence import get_cultural_profile

logger = logging.getLogger(__name__)

cultural_sentiment_app = typer.Typer(
    name="cultural-sentiment",
    help="Analyze sentiment within a specific cultural context."
)


def analyze_regional_sentiment(text: str, country_code: str) -> CulturalSentimentResult:
    """
    Analyzes sentiment of text, interpreted through a cultural lens.

    Args:
        text (str): The input text to analyze.
        country_code (str): The ISO code for the cultural context (e.g., 'JP', 'US').

    Returns:
        CulturalSentimentResult: A Pydantic model with the analysis.
    """
    # 1. Get raw sentiment
    blob = TextBlob(text)
    raw_polarity = blob.sentiment.polarity
    
    if raw_polarity > 0.1:
        raw_sentiment = "positive"
    elif raw_polarity < -0.1:
        raw_sentiment = "negative"
    else:
        raw_sentiment = "neutral"

    # 2. Get cultural profile
    profile = get_cultural_profile(country_code)
    
    interpretation = "No cultural context available. Using raw sentiment."
    interpreted_sentiment = raw_sentiment
    
    if profile:
        # 3. Synthesize and Interpret
        # This is a simple rule-based interpretation. A real system
        # would use a more sophisticated model.
        directness = profile.get("directness", 5) # Scale of 1-10
        
        if directness < 5:
            # High-context, indirect culture (e.g., Japan)
            if raw_sentiment == "neutral":
                interpretation = "NEUTRAL sentiment in a high-context (indirect) culture. This may imply polite disagreement or NEGATIVE sentiment."
                interpreted_sentiment = "potentially_negative"
            elif raw_sentiment == "positive":
                interpretation = "POSITIVE sentiment in a high-context culture. This is a clear signal."
                interpreted_sentiment = "positive"
            else: # negative
                interpretation = "NEGATIVE sentiment in a high-context culture. This indicates a very strong NEGATIVE opinion."
                interpreted_sentiment = "strongly_negative"
        else:
            # Low-context, direct culture (e.g., US, Germany)
            interpretation = "Sentiment from a low-context (direct) culture. Raw sentiment is likely accurate."
            interpreted_sentiment = raw_sentiment

    return CulturalSentimentResult(
        text=text,
        country_code=country_code,
        cultural_profile=profile,
        raw_sentiment=raw_sentiment,
        raw_polarity=raw_polarity,
        interpreted_sentiment=interpreted_sentiment,
        interpretation=interpretation
    )


@cultural_sentiment_app.command("run")
def run_cultural_sentiment_analysis(
    text: str = typer.Argument(..., help="The text to analyze."),
    country_code: str = typer.Option(
        ..., "--country", "-c", help="ISO country code for cultural context (e.g., US, JP, DE)."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes sentiment of text within a specific cultural context.
    """
    with console.status(f"[bold cyan]Analyzing sentiment for {country_code}...[/bold cyan]"):
        results_model = analyze_regional_sentiment(text, country_code.upper())
    
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=f"{country_code}_sentiment",
        module="cultural_sentiment",
        data=results_dict
    )