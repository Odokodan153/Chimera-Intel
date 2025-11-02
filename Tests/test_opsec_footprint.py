"""
Tests for the OpsecFootprint orchestrator module.
"""

import pytest
from unittest.mock import patch, Mock, MagicMock
from chimera_intel.core.opsec_footprint import OpsecFootprint
from chimera_intel.core.schemas import Organization

# Mock the dependent classes
MockFootprint = MagicMock()
MockPersonnelOsint = MagicMock()
MockSocialOsint = MagicMock()
MockCloudOsint = MagicMock()
MockReporter = MagicMock()

@pytest.fixture
def footprint_orchestrator():
    """
    Returns an OpsecFootprint instance with mocked dependencies.
    """
    with patch('chimera_intel.core.opsec_footprint.Footprint', MockFootprint), \
         patch('chimera_intel.core.opsec_footprint.PersonnelOsint', MockPersonnelOsint), \
         patch('chimera_intel.core.opsec_footprint.SocialOsint', MockSocialOsint), \
         patch('chimera_intel.core.opsec_footprint.CloudOsint', MockCloudOsint), \
         patch('chimera_intel.core.opsec_footprint.Reporter', MockReporter):
        
        orchestrator = OpsecFootprint()
        
        # Configure mock return values
        orchestrator.footprint.scan.return_value = {"subdomains": ["a.com"]}
        orchestrator.personnel_osint.scan_organization.return_value = {"employees": ["j.doe"]}
        orchestrator.social_osint.scan_handles.return_value = {"handles": ["@org"]}
        orchestrator.cloud_osint.scan_domain.return_value = {"buckets": ["s3.org"]}
        orchestrator.reporter.generate_report.return_value = "/path/to/report.pdf"
        
        yield orchestrator
        
        # Reset mocks after test
        MockFootprint.reset_mock()
        MockPersonnelOsint.reset_mock()
        MockSocialOsint.reset_mock()
        MockCloudOsint.reset_mock()
        MockReporter.reset_mock()


def test_opsec_footprint_init(footprint_orchestrator):
    assert footprint_orchestrator is not None
    assert isinstance(footprint_orchestrator.footprint, MagicMock)
    assert isinstance(footprint_orchestrator.reporter, MagicMock)

def test_generate_report(footprint_orchestrator):
    org = Organization(
        name="Test Corp",
        domains=["testcorp.com"],
        social_media_handles=["@testcorp"]
    )
    
    report = footprint_orchestrator.generate_report(org)

    # Check that all modules were called
    footprint_orchestrator.footprint.scan.assert_called_with("testcorp.com")
    footprint_orchestrator.cloud_osint.scan_domain.assert_called_with("testcorp.com")
    footprint_orchestrator.personnel_osint.scan_organization.assert_called_with("Test Corp")
    footprint_orchestrator.social_osint.scan_handles.assert_called_with(["@testcorp"])
    
    # Check that findings are compiled
    assert report["domain_footprint"]["subdomains"] == ["a.com"]
    assert report["personnel_exposure"]["employees"] == ["j.doe"]
    assert report["social_media_presence"]["handles"] == ["@org"]
    assert report["cloud_exposure"]["buckets"] == ["s3.org"]
    
    # Check that reporter was called
    footprint_orchestrator.reporter.generate_report.assert_called_once()
    assert report["report_path"] == "/path/to/report.pdf"