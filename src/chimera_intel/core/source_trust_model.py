"""
Module for Source Trust Modeling (GRC).

Provides a constantly updated confidence score for information sources,
ensuring analysts can weight intelligence appropriately.
"""

import typer
import logging
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
import hashlib

from .utils import save_or_print_results, console
from .database import save_scan_to_db, get_db
from .schemas import GRCSourceTrustResult

logger = logging.getLogger(__name__)
source_trust_model_app = typer.Typer()


# Pre-defined trust levels for known source types
# In a real system, this would be a dynamic database.
TRUST_SCORES = {
    "verified_gov": (0.95, "Verified Government Registry"),
    "mainstream_media": (0.75, "Established Media"),
    "corporate_filing": (0.90, "Official Corporate Filing"),
    "fringe_forum": (0.15, "Unverified Fringe Forum"),
    "social_media_unverified": (0.25, "Unverified Social Media"),
    "social_media_verified": (0.60, "Verified Social Media"),
    "default": (0.40, "Unknown/Uncategorized"),
}


def calculate_source_trust(source_identifier: str, source_type: Optional[str] = None) -> GRCSourceTrustResult:
    """
    Calculates the trust score for a given source.
    
    In a real application, this would involve a complex lookup, 
    historical analysis, and reputation modeling.
    """
    logger.info(f"Calculating trust for source: {source_identifier}")
    
    # Use a simple hash for a pseudo-stable score
    base_hash = int(hashlib.md5(source_identifier.encode()).hexdigest(), 16)
    
    if source_type and source_type in TRUST_SCORES:
        base_score, level = TRUST_SCORES[source_type]
    else:
        # Guess type based on identifier
        if any(g in source_identifier for g in ['.gov', '.mil']):
            base_score, level = TRUST_SCORES['verified_gov']
        elif 'forum' in source_identifier or 'chan' in source_identifier:
            base_score, level = TRUST_SCORES['fringe_forum']
        else:
            base_score, level = TRUST_SCORES['default']

    # Add a slight, stable variance based on the identifier
    variance = (base_hash % 10) / 100.0  # +/- 0.09
    final_score = base_score + (variance - 0.045)
    final_score = round(max(0.05, min(0.99, final_score)), 3) # Clamp score

    return GRCSourceTrustResult(
        source_identifier=source_identifier,
        source_type_guess=level,
        trust_score=final_score,
        last_updated="2025-01-01T00:00:00Z" # Mocked timestamp
    )


@source_trust_model_app.command("run")
def run_source_trust_cli(
    source: str = typer.Argument(
        ..., help="The source identifier (e.g., 'example.com', 'twitter_user_123')."
    ),
    source_type: Optional[str] = typer.Option(
        None, "--type", help=f"Optional hint for source type (e.g., {list(TRUST_SCORES.keys())})."
    ),
    target: Optional[str] = typer.Option(
        "default", help="The project target to associate this scan with."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Provides a risk-weighted confidence score for an information source.
    """
    with console.status(
        f"[bold cyan]Analyzing trust for {source}...[/bold cyan]"
    ):
        results_model = calculate_source_trust(source, source_type)

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target, module="source_trust_model", data=results_dict
    )