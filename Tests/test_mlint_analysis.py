# Tests/test_mlint_analysis.py

import pytest
import unittest.mock as mock
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta

# Adjust imports based on the actual project structure
from src.chimera_intel.core.mlint_analysis import detect_layering, detect_straw_company, AMLAlert

@pytest.fixture
def mock_driver():
    """Fixture for a mock Neo4j Driver."""
    driver = MagicMock(name="MockDriver")
    # Mock the session context manager
    mock_session = MagicMock(name="MockSession")
    driver.session.return_value.__enter__.return_value = mock_session
    return driver

@pytest.fixture
def mock_session(mock_driver):
    """Fixture for the mock Neo4j Session."""
    return mock_driver.session.return_value.__enter__.return_value


class TestDetectLayering:

    def test_detects_layering_pattern(self, mock_session):
        """Test successful detection of a layering path."""
        mock_result = MagicMock(name="MockResult")
        mock_result.single.return_value = {
            "path": "mock_path_obj",
            "duration_ms": 120000, # 2 minutes
            "path_length": 4,
            "high_risk_hops": 1,
            "entity_trail": [
                (["Wallet"], {"id": "w1", "name": None}),
                (["Company"], {"id": "c1", "name": "Suspicious Co"}),
                (["Person"], {"id": "p1", "name": "Mr. PEP", "is_pep": True}),
                (["Wallet"], {"id": "w2", "name": None})
            ]
        }
        mock_session.run.return_value = mock_result
        
        alert = detect_layering(mock_session, "w1", "Wallet")
        
        assert alert is not None
        assert isinstance(alert, AMLAlert)
        assert alert.type == "LAYERING"
        assert alert.entity_id == "w1"
        # Score: 0.5 + (4*0.1) + (1*0.2) = 1.1 -> capped at 1.0
        assert alert.confidence == pytest.approx(1.0)
        assert "4-hop" in alert.message
        assert "1 high-risk" in alert.message
        assert "120.00s" in alert.message
        assert alert.evidence["path_length"] == 4
        assert alert.evidence["high_risk_hops"] == 1

    def test_no_alert_for_benign_path(self, mock_session):
        """Test no detection for a path that doesn't meet criteria (e.g., query returns no result)."""
        mock_result = MagicMock(name="MockResult")
        mock_result.single.return_value = None # No path found
        mock_session.run.return_value = mock_result
        
        alert = detect_layering(mock_session, "w1", "Wallet")
        
        assert alert is None

    def test_handles_query_exception(self, mock_session):
        """Test that an exception during query is caught and returns None."""
        mock_session.run.side_effect = Exception("Cypher query failed")
        
        alert = detect_layering(mock_session, "w1", "Wallet")
        
        assert alert is None


class TestDetectStrawCompany:

    def test_detects_clear_straw_company(self, mock_session):
        """Test detection of a high-risk straw company."""
        reg_date = (datetime.utcnow() - timedelta(days=90)).isoformat()
        mock_result = MagicMock(name="MockResult")
        mock_result.single.return_value = {
            "id": "c123",
            "name": "ShadyBiz Ltd",
            "reg_date": reg_date,
            "address": "123 PO Box, Grand Cayman",
            "jurisdiction_name": "Cayman Islands",
            "jurisdiction_risk": 0.8,
            "ubos": [
                {"id": "p789", "is_pep": True, "is_sanctioned": False}
            ]
        }
        mock_session.run.return_value = mock_result

        alert = detect_straw_company(mock_session, "c123")
        
        assert alert is not None
        assert isinstance(alert, AMLAlert)
        assert alert.type == "STRAW_COMPANY"
        assert alert.entity_id == "c123"
        # Score: 0.3 (new) + 0.4 (juris) + 0.5 (pep) + 0.3 (addr) = 1.5 -> capped at 1.0
        assert alert.confidence == pytest.approx(1.0)
        assert "flagged as potential straw/shell" in alert.message
        assert "Recently registered" in alert.evidence["registration"]
        assert "High-risk jurisdiction" in alert.evidence["jurisdiction"]
        assert "p789" in alert.evidence["high_risk_ubos"]
        assert "123 PO Box" in alert.evidence["address"]

    def test_no_alert_for_legit_company(self, mock_session):
        """Test no detection for a legitimate, established company."""
        reg_date = (datetime.utcnow() - timedelta(days=2000)).isoformat()
        mock_result = MagicMock(name="MockResult")
        mock_result.single.return_value = {
            "id": "c456",
            "name": "SolidBiz Inc",
            "reg_date": reg_date,
            "address": "456 Main St, New York",
            "jurisdiction_name": "USA",
            "jurisdiction_risk": 0.2,
            "ubos": [
                {"id": "p111", "is_pep": False, "is_sanctioned": False}
            ]
        }
        mock_session.run.return_value = mock_result
        
        alert = detect_straw_company(mock_session, "c456")
        
        # Confidence = 0.0 (old) + 0.0 (juris) + 0.0 (ubo) + 0.0 (addr) = 0.0. Threshold is 0.6.
        assert alert is None

    def test_no_alert_if_company_not_found(self, mock_session):
        """Test that no alert is returned if the company ID isn't in the graph."""
        mock_result = MagicMock(name="MockResult")
        mock_result.single.return_value = None # No company found
        mock_session.run.return_value = mock_result
        
        alert = detect_straw_company(mock_session, "c999")
        
        assert alert is None