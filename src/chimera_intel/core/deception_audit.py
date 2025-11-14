"""
deception_audit.py

This module provides the DeceptionAudit class, which analyzes an
organization's *own* public communications (social media, blogs)
to find unintentional patterns that an adversary could leverage for
social engineering or deception.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime
import asyncio
from chimera_intel.core.social_media_monitor import monitor_twitter_stream
from chimera_intel.core.web_analyzer import scrape_web_content
from chimera_intel.core.narrative_analyzer import analyze_narrative_gnews
from chimera_intel.core.temporal_analyzer import analyze_temporal_patterns

log = logging.getLogger(__name__)


class DeceptionAudit:
    """
    Analyzes public communications for unintentional consistency or patterns.
    """

    def __init__(self):
        log.info("DeceptionAudit initialized.")
        # No more placeholder classes
        
    async def _fetch_all_comms(self, social_handles: List[str], web_urls: List[str]) -> List[Dict[str, Any]]:
        """(REAL) Helper to fetch all communications into a unified list."""
        all_comms = []
        
        # --- 1. Fetch Social Posts ---
        if social_handles:
            # We'll search for posts *from* a specific user handle
            # monitor_twitter_stream searches for keywords, let's adapt
            # For a real implementation, we'd use a user_timeline endpoint.
            # For this, we'll search for the handle as a keyword.
            query = " OR ".join([f"from:{handle}" for handle in social_handles])
            log.info(f"Fetching social posts with query: {query}")
            # Note: monitor_twitter_stream is sync, run in thread
            social_result = await asyncio.to_thread(monitor_twitter_stream, [query], limit=50)
            
            if not social_result.error and social_result.tweets:
                for tweet in social_result.tweets:
                    all_comms.append({
                        "source": "social",
                        "handle": tweet.author_username,
                        "text": tweet.text,
                        "timestamp": tweet.created_at.isoformat()
                    })

        # --- 2. Fetch Web Page Content ---
        for url in web_urls:
            log.info(f"Fetching web content from: {url}")
            # scrape_web_content is sync, run in thread
            web_result = await asyncio.to_thread(scrape_web_content, url)
            if not web_result.error and web_result.content:
                all_comms.append({
                    "source": "web",
                    "url": url,
                    "text": web_result.content,
                    # We don't have a reliable publish date, so use crawl time
                    "timestamp": datetime.now().isoformat() 
                })
        
        return all_comms

    async def audit_communications(self, social_handles: List[str], web_urls: List[str]) -> Dict[str, Any]:
        """
        (REAL) Runs a full audit on the organization's public communications.

        Args:
            social_handles: List of official social media handles (e.g., 'chimera_intel').
            web_urls: List of official blog/web URLs.

        Returns:
            A dictionary report of detected patterns.
        """
        log.info(f"Starting deception audit for {social_handles} and {web_urls}")

        all_comms = await self._fetch_all_comms(social_handles, web_urls)
        
        if not all_comms:
            return {"error": "No communications found to audit."}
            
        texts = [comm['text'] for comm in all_comms if comm.get('text')]
        timestamps_str = [comm['timestamp'] for comm in all_comms if comm.get('timestamp')]
        
        report = {
            "total_comms_analyzed": len(all_comms),
            "exploitable_patterns": {},
            "narrative_analysis": {},
            "temporal_analysis": {},
        }

        # 1. Analyze messaging content (narrative)
        if texts:
            # We'll use the GNews-based analyzer, but pass it our full text blob
            # as if it were a single article.
            full_text = " ".join(texts)
            # analyze_narrative_gnews is sync, run in thread
            narrative_report = await asyncio.to_thread(analyze_narrative_gnews, full_text)
            report["narrative_analysis"] = narrative_report.model_dump()
            
            # Look for unintentional consistency
            if narrative_report.top_keywords and len(narrative_report.top_keywords) > 3:
                 report["exploitable_patterns"]["messaging_consistency"] = f"High consistency in keyword usage. Top keywords: {', '.join(narrative_report.top_keywords[:3])}"
            
            if narrative_report.sentiment_variance is not None and narrative_report.sentiment_variance < 0.1:
                report["exploitable_patterns"]["sentiment_consistency"] = f"Very low sentiment variance ({narrative_report.sentiment_variance:.2f}), highly predictable tone."

        # 2. Analyze messaging timing (temporal)
        if timestamps_str:
            # analyze_temporal_patterns is sync, run in thread
            temporal_report = await asyncio.to_thread(analyze_temporal_patterns, timestamps_str)
            report["temporal_analysis"] = temporal_report.model_dump()
            
            # Look for exploitable timing patterns
            if temporal_report.peak_day_of_week:
                report["exploitable_patterns"]["timing_pattern_day"] = f"Majority of posts occur on {temporal_report.peak_day_of_week}."
            if temporal_report.peak_hour_of_day is not None:
                report["exploitable_patterns"]["timing_pattern_hour"] = f"Peak posting hour is {temporal_report.peak_hour_of_day}:00 UTC."

        log.info(f"Deception audit complete. Found patterns: {report['exploitable_patterns']}")
        return report