"""
persona_profiler.py

This module provides the PersonaProfiler class and the 'persona_app'
Typer app for CLI interaction.
"""

import logging
import typer
import json
from typing import Dict, Any
from datetime import datetime, timedelta
from typing_extensions import Annotated
from chimera_intel.core.social_osint import SocialOsint
from chimera_intel.core.temporal_analyzer import TemporalAnalyzer
from chimera_intel.core.advanced_media_analysis import AdvancedMediaAnalysis

log = logging.getLogger(__name__)


class PersonaProfiler:
    """
    Applies HUMINT search and analysis tools to detect adversarial personas.
    """
    # ... (All the class logic from my first response goes here) ...
    # __init__, profile_persona
    def __init__(self):
        log.info("PersonaProfiler initialized.")
        self.social_osint = SocialOsint()
        self.temporal_analyzer = TemporalAnalyzer()
        self.media_analysis = AdvancedMediaAnalysis()

    def profile_persona(self, handle: str, platform: str) -> Dict[str, Any]:
        """
        Analyzes a single persona for inconsistencies.

        Args:
            handle: The username/handle of the persona.
            platform: The platform (e.g., 'twitter', 'forum').

        Returns:
            A dictionary containing the analysis and risk flags.
        """
        log.info(f"Profiling persona: {handle} on {platform}")
        
        try:
            # 1. Fetch profile and post data
            # Assuming social_osint returns structured data
            profile_data = self.social_osint.get_profile(handle, platform)
            posts = self.social_osint.get_posts(handle, platform, limit=100)
            
            if not profile_data:
                return {"error": "Profile not found."}

            analysis = {
                "handle": handle,
                "platform": platform,
                "profile_data": profile_data,
                "flags": [],
                "analysis_details": {}
            }

            # 2. Analyze creation date
            creation_date_str = profile_data.get('join_date') or profile_data.get('created_at')
            if creation_date_str:
                # Basic parsing, platform-specific logic would be needed
                creation_date = datetime.fromisoformat(creation_date_str.replace('Z', '+00:00'))
                if creation_date > (datetime.now(creation_date.tzinfo) - timedelta(days=90)):
                    analysis["flags"].append("RECENT_CREATION_DATE")
            
            # 3. Analyze posting times
            if posts:
                timestamps = [post.get('created_at') for post in posts if post.get('created_at')]
                if timestamps:
                    ts_objects = [datetime.fromisoformat(ts.replace('Z', '+00:00')) for ts in timestamps]
                    temporal_patterns = self.temporal_analyzer.find_activity_patterns(ts_objects)
                    analysis["analysis_details"]["temporal_patterns"] = temporal_patterns
                    
                    # Flag if activity is 24/7 or highly erratic
                    if temporal_patterns.get('periodicity') == 'erratic':
                         analysis["flags"].append("ERRATIC_POSTING_TIMES")

            # 4. Analyze profile image
            image_url = profile_data.get('profile_image_url')
            if image_url:
                image_report = self.media_analysis.reverse_image_search(image_url)
                analysis["analysis_details"]["image_analysis"] = image_report
                
                # Flag if image is a known stock photo or used elsewhere
                if image_report.get('is_stock_photo'):
                    analysis["flags"].append("RECYCLED_IMAGE_STOCK")
                if image_report.get('match_count', 0) > 5: # Arbitrary threshold
                    analysis["flags"].append("RECYCLED_IMAGE_MULTIPLE_PROFILES")

            log.info(f"Profiling complete for {handle}. Found flags: {analysis['flags']}")
            return analysis

        except Exception as e:
            log.error(f"Error during persona profiling: {e}", exc_info=True)
            return {"error": str(e)}

# --- NEW TYPER APP ---
# This app will be imported by the new plugin
persona_app = typer.Typer(help="Profiles personas for sock puppet indicators.")

@persona_app.command(help="Profile a persona for sock puppet indicators.")
def profile(
    handle: Annotated[str, typer.Option(help="The persona's username/handle.")],
    platform: Annotated[str, typer.Option(help="The platform (e.g., twitter, reddit).")]
):
    """
    CLI command to run the persona profiler.
    """
    typer.echo(f"Profiling {handle} on {platform}...")
    profiler = PersonaProfiler()
    
    try:
        report = profiler.profile_persona(handle, platform)
        typer.echo(json.dumps(report, indent=2, default=str))
    except Exception as e:
        typer.secho(f"Error during profiling: {e}", fg=typer.colors.RED)