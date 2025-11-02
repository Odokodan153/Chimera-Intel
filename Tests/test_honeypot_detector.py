"""
Tests for the HoneypotDetector module.
"""

import pytest
from unittest.mock import patch, Mock
from chimera_intel.core.honeypot_detector import HoneypotDetector

@pytest.fixture
def detector():
    """Returns a HoneypotDetector instance."""
    return HoneypotDetector()

def test_detector_init(detector):
    assert detector is not None
    assert "canarytokens.com" in detector.domains

def test_scan_text_content_clean(detector):
    content = "This is a normal email body with no links."
    findings = detector.scan_text_content(content)
    assert not findings["tracking_pixels"]
    assert not findings["honeypot_urls"]
    assert not findings["honeypot_ips"]

def test_scan_text_content_with_honeypot_url(detector):
    content = "Please click this link: http://canarytokens.com/tracker"
    findings = detector.scan_text_content(content)
    assert not findings["tracking_pixels"]
    assert len(findings["honeypot_urls"]) == 1
    assert findings["honeypot_urls"][0] == "http://canarytokens.com/tracker"

def test_scan_text_content_with_honeypot_ip(detector):
    content = "Our server is at 198.51.100.5, please connect."
    findings = detector.scan_text_content(content)
    assert len(findings["honeypot_ips"]) == 1
    assert findings["honeypot_ips"][0] == "198.51.100.5"

def test_scan_text_content_with_tracking_pixel(detector):
    content = 'Hello <img src="http://track.example.com/pixel.png" height="1" width="1" style="display:none;">'
    findings = detector.scan_text_content(content)
    assert len(findings["tracking_pixels"]) == 1
    assert findings["tracking_pixels"][0] == "http://track.example.com/pixel.png"
    assert len(findings["honeypot_urls"]) == 1 # Also caught by URL check

def test_scan_email_headers_suspicious(detector):
    headers = {
        "Received": ["from mail.badguydomain.com (198.51.100.5)"],
        "X-Canary": "Test-Token"
    }
    findings = detector.scan_email_headers(headers)
    assert len(findings["suspicious_headers"]) == 1
    assert "X-Canary" in findings["suspicious_headers"]
    assert len(findings["honeypot_ips"]) == 1
    assert "198.51.100.5" in findings["honeypot_ips"]

def test_scan_file_metadata(detector):
    metadata = {
        "Author": "John Doe",
        "Comments": "Link to resources: http://canarytokens.com/doc"
    }
    findings = detector.scan_file_metadata(metadata)
    assert len(findings["honeypot_urls"]) == 1
    assert "http://canarytokens.com/doc" in findings["honeypot_urls"]