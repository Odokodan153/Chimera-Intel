"""
Reputation Degradation Modeling Module for Chimera Intel.

Predicts the potential damage of a deepfake or manipulated image
by modeling its amplification network and projecting the impact over time.
"""

import typer
import logging
import pandas as pd
from chimera_intel.core.schemas import ReputationModelResult
from typing import List, Optional
from statsmodels.tsa.arima.model import ARIMA
from chimera_intel.core.narrative_analyzer import track_narrative
from chimera_intel.core.advanced_media_analysis import SyntheticMediaAudit
from chimera_intel.core.utils import console, save_or_print_results

logger = logging.getLogger(__name__)

# --- Enhanced Heuristic: Source Tiers ---

# Define impact tiers for known news sources.
SOURCE_TIER_MAP = {
    # Tier 1: Top-tier global wire services & financial news
    "Reuters": 25,
    "Associated Press": 25,
    "Bloomberg": 25,
    "The New York Times": 20,
    "The Wall Street Journal": 20,
    
    # Tier 2: Major national / international broadcasters and papers
    "BBC News": 15,
    "CNN": 15,
    "The Guardian": 15,
    "Fox News": 12, # Impact is high regardless of leaning
    "MSNBC": 12,
    "The Washington Post": 12,
    
    # Tier 3: Major online publications & tabloids (high velocity)
    "TechCrunch": 8,
    "The Verge": 8,
    "Daily Mail": 7,
    "BuzzFeed News": 7,
    
    # Tier 4: Default for unlisted/regional news or blogs
    "default": 3,
    
    # Tier 5: Social Media (base score, amplified by sentiment)
    "Tweet": 1
}

def _get_amplification_network_strength(query: str) -> float:
    """
    Analyzes the current narrative to find its amplification strength
    based on a tiered source model.
    """
    logger.info(f"Getting amplification network for: {query}")
    try:
        narrative_items = track_narrative(query)
        if not narrative_items:
            return 0.0
        
        strength = 0.0
        for item in narrative_items:
            base_score = 1.0
            
            if item['type'] == 'Tweet':
                base_score = SOURCE_TIER_MAP["Tweet"]
            elif item['type'] == 'News':
                source_name = item["source"]
                # Find the closest match in our tier map
                tier_score = SOURCE_TIER_MAP["default"]
                for tier_name, score in SOURCE_TIER_MAP.items():
                    if tier_name.lower() in source_name.lower():
                        tier_score = score
                        break
                base_score = tier_score
            
            # Negative sentiment is a powerful amplifier for reputation damage
            if item['sentiment'].lower() == 'negative':
                base_score *= 1.75
            
            strength += base_score
        
        return min(strength, 100.0) # Cap at 100 for normalization
    except Exception as e:
        logger.warning(f"Could not get amplification network: {e}")
        return 0.0

def _project_timeline(initial_impact: float) -> List[float]:
    """
    Uses an ARIMA model to project the impact score over 7 days.
    Reuses the logic from StrategicForecaster.
    """
    logger.info("Projecting impact timeline...")
    try:
        # Create a simulated "historical" trend
        historical_data = [
            max(0.1, initial_impact * 0.1), 
            max(0.1, initial_impact * 0.2), 
            max(0.1, initial_impact * 0.4), 
            max(0.1, initial_impact * 0.7), 
            max(0.1, initial_impact) # Ensure non-zero
        ]
        
        data_series = pd.Series(historical_data)

        # Fit an ARIMA model (AutoRegressive, Integrated, Moving Average)
        model = ARIMA(data_series, order=(1, 1, 1))
        model_fit = model.fit()
        
        # Forecast the next 7 periods (days)
        forecast = model_fit.forecast(steps=7)
        
        # Ensure forecast doesn't go negative and cap at 10
        cleaned_forecast = [round(max(0, min(f, 10.0)), 2) for f in forecast.tolist()]
        return cleaned_forecast
        
    except Exception as e:
        logger.error(f"Could not generate forecast timeline: {e}")
        # Fallback to a simple linear decay
        return [round(max(0, initial_impact - i), 2) for i in range(1, 8)]


def model_reputation_degradation(query: str, media_file: str) -> ReputationModelResult:
    """
    Models the potential reputational damage of a deepfake.
    """
    logger.info(f"Modeling reputation degradation for: {query}")
    try:
        # 1. Analyze the deepfake's quality/believability
        logger.info(f"Auditing media file: {media_file}")
        media_audit = SyntheticMediaAudit(media_file).analyze()
        media_confidence = media_audit.confidence
        
        # 2. Analyze the amplification network
        network_strength = _get_amplification_network_strength(query)
        
        # 3. Calculate Projected Impact Score (Heuristic)
        # Impact = (Media Quality/Believability) * (Network Strength / 10)
        # (Network strength is 0-100, this normalizes it to 0-10)
        impact_score = (media_confidence * (network_strength / 10.0))
        impact_score = round(max(0.0, min(impact_score, 10.0)), 2)

        if impact_score >= 7.0:
            risk_level = "Critical"
        elif impact_score >= 4.0:
            risk_level = "High"
        elif impact_score >= 2.0:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # 4. Project the timeline
        timeline = _project_timeline(impact_score)

        return ReputationModelResult(
            query=query,
            media_file=media_file,
            media_synthetic_confidence=media_audit.confidence,
            amplification_network_strength=network_strength,
            projected_impact_score=impact_score,
            risk_level=risk_level,
            projected_impact_timeline=timeline
        )

    except Exception as e:
        logger.error(f"Error in reputation degradation modeling: {e}", exc_info=True)
        return ReputationModelResult(
            query=query, 
            media_file=media_file,
            projected_impact_score=0.0,
            error=str(e)
        )

# --- CLI Application ---

reputation_app = typer.Typer(
    name="reputation",
    help="Reputation Degradation Modeling.",
)

@reputation_app.command(
    "reputation-degradation-model",
    help="Predict the impact and timeline of a deepfake or narrative attack.",
)
def run_reputation_degradation_model(
    query: str = typer.Argument(..., help="The narrative or keyword associated with the media."),
    media_file: str = typer.Argument(..., help="Path to the deepfake/manipulated media file."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Models the potential damage of a deepfake by analyzing its quality
    and the strength of the narrative network amplifying it.
    """
    console.print(f"[bold cyan]Running reputation degradation model...[/bold cyan]")
    console.print(f"  - Narrative: '{query}'")
    console.print(f"  - Media: '{media_file}'")
    
    result = model_reputation_degradation(query, media_file)
    
    save_or_print_results(result.model_dump(), output_file)
    
    console.print(f"\n[bold]Projected Impact Score:[/bold] [red]{result.projected_impact_score:.2f} / 10.0[/red] ([bold]{result.risk_level}[/bold])")
    console.print(f"  - Media Synthetic Confidence: {result.media_synthetic_confidence:.2f}")
    console.print(f"  - Amplification Network Strength (0-100): {result.amplification_network_strength:.2f}")
    console.print(f"[bold]Projected 7-Day Impact Timeline:[/bold] {result.projected_impact_timeline}")