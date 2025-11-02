"""
honeypot_detector.py

This module provides the HoneypotDetector class and the 'honeypot_app'
Typer app for CLI interaction.
"""

import logging
import re
import typer
import json
from typing import List, Dict, Any, Set
from typing_extensions import Annotated

log = logging.getLogger(__name__)

# This list should be populated from a dedicated threat intel feed or config
KNOWN_HONEYPOT_DOMAINS: Set[str] = {
    "canarytokens.com",
    "track.example.com",
    "honeypot.org",
}

KNOWN_HONEYPOT_IPS: Set[str] = {
    "192.0.2.1",
    "198.51.100.5",
}

# Regex to find common tracking pixels (1x1 images)
TRACKING_PIXEL_REGEX = re.compile(
    r'<img\s+[^>]*src\s*=\s*["\'](http[^"\']+)["\'][^>]*height\s*=\s*["\']1["\'][^>]*width\s*=\s*["\']1["\']'
)
URL_REGEX = re.compile(r'https?://([^\s/$.?#].[^\s]*)')
IP_REGEX = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')


class HoneypotDetector:
    """
    Scans collected data for signs of honeypots and intelligence collection.
    """
    # ... (All the class logic from my first response goes here) ...
    # __init__, _check_url, _check_ip, scan_text_content,
    # scan_email_headers, scan_file_metadata
    def __init__(self):
        log.info("HoneypotDetector initialized.")
        self.domains = KNOWN_HONEYPOT_DOMAINS
        self.ips = KNOWN_HONEYPOT_IPS

    def _check_url(self, url: str) -> bool:
        """Checks a single URL's domain against the known list."""
        try:
            domain = url.split('/')[2]
            if domain in self.domains:
                log.warning(f"Known honeypot domain detected: {domain}")
                return True
        except IndexError:
            log.debug(f"Could not parse domain from URL: {url}")
        return False

    def _check_ip(self, ip: str) -> bool:
        """Checks a single IP against the known list."""
        if ip in self.ips:
            log.warning(f"Known honeypot IP detected: {ip}")
            return True
        return False

    def scan_text_content(self, content: str) -> Dict[str, List[str]]:
        """
        Scans a block of text (like an email body or webpage content)
        for honeypot indicators.
        """
        findings = {
            "tracking_pixels": [],
            "honeypot_urls": [],
            "honeypot_ips": [],
        }

        # 1. Check for tracking pixels
        for match in TRACKING_PIXEL_REGEX.finditer(content):
            findings["tracking_pixels"].append(match.group(1))

        # 2. Check for known URLs
        for url_match in URL_REGEX.finditer(content):
            url = url_match.group(0)
            if self._check_url(url):
                findings["honeypot_urls"].append(url)

        # 3. Check for known IPs
        for ip_match in IP_REGEX.finditer(content):
            ip = ip_match.group(0)
            if self._check_ip(ip):
                findings["honeypot_ips"].append(ip)

        log.info(f"Text scan complete. Found {len(findings['honeypot_urls'])} URLs, {len(findings['honeypot_ips'])} IPs.")
        return findings

    def scan_email_headers(self, headers: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Scans email headers for suspicious 'Received' fields or custom
        tracking headers.
        """
        findings = {
            "suspicious_headers": [],
            "honeypot_ips": [],
        }

        # Check 'Received' headers for known bad IPs
        received_headers = headers.get('Received', [])
        if not isinstance(received_headers, list):
            received_headers = [received_headers]

        for header in received_headers:
            for ip_match in IP_REGEX.finditer(header):
                ip = ip_match.group(0)
                if self._check_ip(ip):
                    findings["honeypot_ips"].append(ip)

        # Check for common Canary Token headers
        if headers.get('X-Canary'):
            findings['suspicious_headers'].append('X-Canary')
        if headers.get('X-Track'):
            findings['suspicious_headers'].append('X-Track')

        log.info(f"Header scan complete. Found {len(findings['suspicious_headers'])} headers.")
        return findings

    def scan_file_metadata(self, metadata: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Scans file metadata (e.g., PDF author, DOCX properties) for
        embedded honeypot links or identifiers.
        """
        findings = {
            "honeypot_urls": [],
        }
        
        # Simple scan: iterate over all string values in metadata
        for key, value in metadata.items():
            if isinstance(value, str):
                for url_match in URL_REGEX.finditer(value):
                    url = url_match.group(0)
                    if self._check_url(url):
                        findings["honeypot_urls"].append(url)
        
        log.info(f"Metadata scan complete. Found {len(findings['honeypot_urls'])} URLs.")
        return findings

# --- NEW TYPER APP ---
# This app will be imported by the new plugin
honeypot_app = typer.Typer(help="Detects honeypots and collection infrastructure.")

@honeypot_app.command(help="Scan text content for honeypot indicators.")
def scan_text(
    text: Annotated[str, typer.Option(help="Text content to scan.")]
):
    detector = HoneypotDetector()
    results = detector.scan_text_content(text)
    typer.echo(json.dumps(results, indent=2))

@honeypot_app.command(help="Scan a file's metadata for honeypot indicators.")
def scan_meta(
    file_path: Annotated[typer.Path, typer.Option(exists=True, help="File to scan.")]
):
    # This is a simplified example.
    # In a real implementation, you'd use a library to extract metadata.
    typer.echo(f"Simulating metadata scan for {file_path}")
    metadata = {
        "Creator": "Test User",
        "Source": "http://canarytokens.com/test.pdf"
    }
    detector = HoneypotDetector()
    results = detector.scan_file_metadata(metadata)
    typer.echo(json.dumps(results, indent=2))