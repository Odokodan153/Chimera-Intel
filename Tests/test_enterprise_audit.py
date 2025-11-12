"""
Tests for the Enterprise Auditor
"""

import pytest
from unittest.mock import patch, MagicMock

from chimera_intel.core.enterprise_audit import EnterpriseAuditor

@pytest.fixture
def mock_audit_logger():
    with patch("chimera_intel.core.audit_logger.AuditLogger") as mock:
        mock.return_value.log_audit = MagicMock()
        yield mock

def test_log_investigation_start(mock_audit_logger):
    auditor = EnterpriseAuditor(tenant_id="audit_tenant")
    auditor.log_investigation_start(identifier="acme.com", user="test_user")
    
    mock_log = mock_audit_logger.return_value.log_audit
    mock_log.assert_called_once()
    
    call_args = mock_log.call_args[0][0]
    assert call_args["event_type"] == "INVESTIGATION_START"
    assert call_args["tenant_id"] == "audit_tenant"
    assert call_args["status"] == "success"
    assert call_args["target"] == "acme.com"
    assert call_args["user"] == "test_user"

def test_log_alert_triggered(mock_audit_logger):
    auditor = EnterpriseAuditor(tenant_id="audit_tenant_2")
    details = {"score": 95}
    auditor.log_alert_triggered("CRITICAL_EXPOSURE", details)
    
    mock_log = mock_audit_logger.return_value.log_audit
    mock_log.assert_called_once()
    
    call_args = mock_log.call_args[0][0]
    assert call_args["event_type"] == "ALERT_TRIGGERED"
    assert call_args["tenant_id"] == "audit_tenant_2"
    assert call_args["score"] == 95