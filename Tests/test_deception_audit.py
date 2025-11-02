"""
Tests for the DeceptionAudit module.
"""

import pytest
from unittest.mock import patch, Mock, MagicMock
from datetime import datetime
from chimera_intel.core.deception_audit import DeceptionAudit

# Mock dependent classes
MockSocialMediaMonitor = MagicMock()
MockWebAnalyzer = MagicMock()
MockNarrativeAnalyzer = MagicMock()
MockTemporalAnalyzer = MagicMock()

@pytest.fixture
def auditor():
    """
    Returns a DeceptionAudit instance with mocked dependencies.
    """
    with patch('chimera_intel.core.deception_audit.SocialMediaMonitor', MockSocialMediaMonitor), \
         patch('chimera_intel.core.deception_audit.WebAnalyzer', MockWebAnalyzer), \
         patch('chimera_intel.core.deception_audit.NarrativeAnalyzer', MockNarrativeAnalyzer), \
         patch('chimera_intel.core.deception_audit.TemporalAnalyzer', MockTemporalAnalyzer):
        
        auditor = DeceptionAudit()

        # Mock fetch methods
        auditor.social_monitor.get_recent_posts.return_value = [
            {"text": "Big news on Friday!", "created_at": "2023-10-27T16:00:00Z"} # Friday
        ]
        auditor.web_analyzer.scrape_articles.return_value = [
            {"text": "Our quarterly report.", "publish_date": "2023-10-20T16:01:00Z"} # Friday
        ]

        # Mock analysis methods
        auditor.narrative_analyzer.find_patterns.return_value = {
            "top_keywords_count": 15, "sentiment_variance": 0.05
        }
        auditor.temporal_analyzer.find_posting_frequency.return_value = {
            "peak_day": "Friday", "peak_hour": 16
        }
        
        yield auditor
        
        # Reset mocks
        MockSocialMediaMonitor.reset_mock()
        MockWebAnalyzer.reset_mock()
        MockNarrativeAnalyzer.reset_mock()
        MockTemporalAnalyzer.reset_mock()

def test_auditor_init(auditor):
    assert auditor is not None
    assert isinstance(auditor.narrative_analyzer, MagicMock)

def test_audit_communications(auditor):
    social = ["@OrgHandle"]
    web = ["blog.org.com"]
    
    report = auditor.audit_communications(social, web)

    # Check that fetchers were called
    auditor.social_monitor.get_recent_posts.assert_called_with("@OrgHandle")
    auditor.web_analyzer.scrape_articles.assert_called_with("blog.org.com")
    
    # Check that analyzers were called
    auditor.narrative_analyzer.find_patterns.assert_called()
    auditor.temporal_analyzer.find_posting_frequency.assert_called()
    
    assert report["total_comms_analyzed"] == 2
    
    # Check for exploitable patterns
    patterns = report["exploitable_patterns"]
    assert "messaging_consistency" in patterns
    assert "sentiment_consistency" in patterns
    assert "timing_pattern_day" in patterns
    assert "timing_pattern_hour" in patterns
    assert "Friday" in patterns["timing_pattern_day"]
    assert "16" in str(patterns["timing_pattern_hour"])