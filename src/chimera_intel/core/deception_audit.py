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
from chimera_intel.core.social_media_monitor import SocialMediaMonitor
from chimera_intel.core.web_analyzer import WebAnalyzer
from chimera_intel.core.narrative_analyzer import NarrativeAnalyzer
from chimera_intel.core.temporal_analyzer import TemporalAnalyzer

log = logging.getLogger(__name__)


class DeceptionAudit:
    """
    Analyzes public communications for unintentional consistency or patterns.
    """

    def __init__(self):
        log.info("DeceptionAudit initialized.")
        self.social_monitor = SocialMediaMonitor()
        self.web_analyzer = WebAnalyzer()
        self.narrative_analyzer = NarrativeAnalyzer()
        self.temporal_analyzer = TemporalAnalyzer()

    def _fetch_all_comms(self, social_handles: List[str], web_urls: List[str]) -> List[Dict[str, Any]]:
        """Helper to fetch all communications into a unified list."""
        all_comms = []
        
        for handle in social_handles:
            # Assuming monitor returns a list of posts
            posts = self.social_monitor.get_recent_posts(handle)
            for post in posts:
                all_comms.append({
                    "source": "social",
                    "handle": handle,
                    "text": post.get('text'),
                    "timestamp": post.get('created_at')
                })

        for url in web_urls:
            # Assuming analyzer returns blog posts/articles
            articles = self.web_analyzer.scrape_articles(url)
            for article in articles:
                 all_comms.append({
                    "source": "web",
                    "url": url,
                    "text": article.get('text'),
                    "timestamp": article.get('publish_date')
                })
        
        return all_comms

    def audit_communications(self, social_handles: List[str], web_urls: List[str]) -> Dict[str, Any]:
        """
        Runs a full audit on the organization's public communications.

        Args:
            social_handles: List of official social media handles.
            web_urls: List of official blog/web URLs.

        Returns:
            A dictionary report of detected patterns.
        """
        log.info(f"Starting deception audit for {social_handles} and {web_urls}")

        all_comms = self._fetch_all_comms(social_handles, web_urls)
        
        if not all_comms:
            return {"error": "No communications found to audit."}
            
        texts = [comm['text'] for comm in all_comms if comm['text']]
        timestamps = [comm['timestamp'] for comm in all_comms if comm['timestamp']]
        
        report = {
            "total_comms_analyzed": len(all_comms),
            "exploitable_patterns": {},
            "narrative_analysis": {},
            "temporal_analysis": {},
        }

        # 1. Analyze messaging content (narrative)
        if texts:
            narrative_report = self.narrative_analyzer.find_patterns(texts)
            report["narrative_analysis"] = narrative_report
            # Look for unintentional consistency
            if narrative_report.get('top_keywords_count', 0) > 10:
                report["exploitable_patterns"]["messaging_consistency"] = "High consistency in keyword usage."
            if narrative_report.get('sentiment_variance', 1.0) < 0.1:
                report["exploitable_patterns"]["sentiment_consistency"] = "Very low sentiment variance."

        # 2. Analyze messaging timing (temporal)
        if timestamps:
            ts_objects = [datetime.fromisoformat(ts.replace('Z', '+00:00')) for ts in timestamps]
            temporal_report = self.temporal_analyzer.find_posting_frequency(ts_objects)
            report["temporal_analysis"] = temporal_report
            
            # Look for exploitable timing patterns
            peak_day = temporal_report.get('peak_day')
            if peak_day:
                report["exploitable_patterns"]["timing_pattern_day"] = f"Majority of posts occur on {peak_day}."
            peak_hour = temporal_report.get('peak_hour')
            if peak_hour is not None:
                report["exploitable_patterns"]["timing_pattern_hour"] = f"Peak posting hour is {peak_hour}:00."

        log.info(f"Deception audit complete. Found patterns: {report['exploitable_patterns']}")
        return report