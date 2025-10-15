import unittest
import json
from chimera_intel.core.stix_converter import StixConverter
from chimera_intel.core.schemas import (
    FootprintResult,
    VulnerabilityScanResult,
    ThreatActor,
    TTP,
)


class TestStixConverter(unittest.TestCase):
    """Test cases for the STIX2 bundle converter."""

    def setUp(self):
        """Set up the test data for conversion."""
        # --- Comprehensive and Valid Footprint Data ---

        self.footprint_data = {
            "domain": "example.com",
            "footprint": {
                "whois_info": {"registrar": "Test Registrar"},
                "dns_records": {"A": ["192.0.2.1"]},
                "subdomains": {
                    "total_unique": 1,
                    "results": [
                        {
                            "domain": "sub.example.com",
                            "confidence": "High",
                            "sources": ["DNS"],
                        }
                    ],
                },
                "ip_threat_intelligence": [
                    {
                        "indicator": "192.0.2.1",
                        "is_malicious": True,
                        "pulse_count": 5,
                        "pulses": [
                            {
                                "name": "Malicious C2",
                                "malware_families": ["GenericBot"],
                                "tags": ["C2"],
                            }
                        ],
                    }
                ],
                "historical_dns": {
                    "a_records": ["198.51.100.1"],
                    "aaaa_records": [],
                    "mx_records": [],
                },
                "reverse_ip": {"192.0.2.1": ["host.example.com"]},
                "asn_info": {"192.0.2.1": {"asn": "AS12345", "owner": "Test ISP"}},
                "tls_cert_info": {
                    "issuer": "Test CA",
                    "subject": "example.com",
                    "sans": ["example.com"],
                    "not_before": "2023-01-01T00:00:00",
                    "not_after": "2024-01-01T00:00:00",
                },
                "dnssec_info": {
                    "dnssec_enabled": True,
                    "spf_record": "v=spf1 ...",
                    "dmarc_record": "v=DMARC1 ...",
                },
                "ip_geolocation": {
                    "192.0.2.1": {
                        "ip": "192.0.2.1",
                        "city": "Test City",
                        "country": "TC",
                    }
                },
                "cdn_provider": "Test CDN",
                "breach_info": {"source": "HIBP", "breaches": ["TestBreach"]},
                "port_scan_results": {"192.0.2.1": {"open_ports": {80: "http"}}},
                "web_technologies": {"cms": "WordPress"},
                "personnel_info": {
                    "employees": [{"name": "John Doe", "email": "j.doe@example.com"}]
                },
                "knowledge_graph": {"nodes": [], "edges": []},
            },
        }

        self.vuln_scan_data = {
            "target_domain": "example.com",
            "scanned_hosts": [
                {
                    "host": "192.0.2.1",
                    "state": "up",
                    "open_ports": [
                        {
                            "port": 443,
                            "state": "open",
                            "service": "https",
                            "vulnerabilities": [
                                {
                                    "id": "CVE-2023-0001",
                                    "cvss": 9.8,
                                    "title": "Critical RCE",
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        self.threat_actor_data = {
            "actor": {
                "name": "Test Actor",
                "aliases": ["TA"],
                "known_ttps": [
                    {
                        "technique_id": "T1566.001",
                        "tactic": "Initial Access",
                        "description": "Phishing",
                    }
                ],
            }
        }

    def test_create_stix_bundle_with_all_data_types(self):
        """
        Tests the creation of a STIX bundle with various data types.
        """
        # --- Arrange ---
        # Validate the mock data against the Pydantic models

        footprint_result = FootprintResult.model_validate(self.footprint_data)
        vuln_result = VulnerabilityScanResult.model_validate(self.vuln_scan_data)
        actor_result = ThreatActor.model_validate(self.threat_actor_data["actor"])

        converter = StixConverter("Test Project")
        converter.add_scan_result(footprint_result)
        converter.add_scan_result(vuln_result)
        converter.add_threat_actor(actor_result)

        # --- Act ---

        bundle = converter.create_bundle()
        bundle_dict = json.loads(bundle.serialize(pretty=True))

        # --- Assert ---

        self.assertEqual(bundle.type, "bundle")
        self.assertGreater(
            len(bundle.objects), 5
        )  # Identity, Report, Domain, IP, Vuln, etc.

        # Verify key objects were created

        object_types = [obj["type"] for obj in bundle_dict["objects"]]
        self.assertIn("identity", object_types)
        self.assertIn("report", object_types)
        self.assertIn("domain-name", object_types)
        self.assertIn("ipv4-addr", object_types)
        self.assertIn("vulnerability", object_types)
        self.assertIn("threat-actor", object_types)
        self.assertIn("attack-pattern", object_types)
