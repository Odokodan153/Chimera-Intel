"""
Tests for the PersonaProfiler module.
"""

import pytest
from unittest.mock import patch, Mock, MagicMock
from datetime import datetime, timedelta
from chimera_intel.core.persona_profiler import PersonaProfiler

# Mock the dependent classes
MockSocialOsint = MagicMock()
MockTemporalAnalyzer = MagicMock()
MockAdvancedMediaAnalysis = MagicMock()

@pytest.fixture
def profiler():
    """
    Returns a PersonaProfiler instance with mocked dependencies.
    """
    with patch('chimera_intel.core.persona_profiler.SocialOsint', MockSocialOsint), \
         patch('chimera_intel.core.persona_profiler.TemporalAnalyzer', MockTemporalAnalyzer), \
         patch('chimera_intel.core.persona_profiler.AdvancedMediaAnalysis', MockAdvancedMediaAnalysis):
        
        profiler = PersonaProfiler()
        
        # Configure mock return values
        profiler.social_osint.get_profile.return_value = {
            "join_date": (datetime.now() - timedelta(days=30)).isoformat() + "Z",
            "profile_image_url": "http://example.com/img.png"
        }
        profiler.social_osint.get_posts.return_value = [
            {"created_at": (datetime.now() - timedelta(hours=h)).isoformat() + "Z"} for h in range(1, 25, 5)
        ]
        profiler.temporal_analyzer.find_activity_patterns.return_value = {"periodicity": "erratic"}
        profiler.media_analysis.reverse_image_search.return_value = {"is_stock_photo": True, "match_count": 2}
        
        yield profiler
        
        # Reset mocks
        MockSocialOsint.reset_mock()
        MockTemporalAnalyzer.reset_mock()
        MockAdvancedMediaAnalysis.reset_mock()

def test_profiler_init(profiler):
    assert profiler is not None
    assert isinstance(profiler.social_osint, MagicMock)
    assert isinstance(profiler.temporal_analyzer, MagicMock)

def test_profile_persona_flags(profiler):
    report = profiler.profile_persona("sock_puppet", "twitter")

    # Check that modules were called
    profiler.social_osint.get_profile.assert_called_with("sock_puppet", "twitter")
    profiler.social_osint.get_posts.assert_called_with("sock_puppet", "twitter", limit=100)
    profiler.temporal_analyzer.find_activity_patterns.assert_called()
    profiler.media_analysis.reverse_image_search.assert_called_with("http://example.com/img.png")
    
    # Check for flags
    assert "RECENT_CREATION_DATE" in report["flags"]
    assert "ERRATIC_POSTING_TIMES" in report["flags"]
    assert "RECYCLED_IMAGE_STOCK" in report["flags"]
    assert "RECYCLED_IMAGE_MULTIPLE_PROFILES" not in report["flags"] # match_count was too low

def test_profile_persona_clean(profiler):
    # Override mocks for a "clean" profile
    profiler.social_osint.get_profile.return_value = {
        "join_date": (datetime.now() - timedelta(days=500)).isoformat() + "Z",
        "profile_image_url": "http://example.com/unique.png"
    }
    profiler.temporal_analyzer.find_activity_patterns.return_value = {"periodicity": "daily"}
    profiler.media_analysis.reverse_image_search.return_value = {"is_stock_photo": False, "match_count": 0}
    
    report = profiler.profile_persona("real_user", "twitter")

    assert not report["flags"]