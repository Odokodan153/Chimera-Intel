import unittest
import json
from chimera_intel.core import stix_converter
from stix2 import Bundle


class TestStixConverter(unittest.TestCase):
    """Test cases for the STIX2 bundle converter functions."""

    def setUp(self):
        """Set up the test data for conversion."""
        self.footprint_data = {
            "domain": "example.com",
            "footprint": {
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
                    }
                ],
                "whois_info": {},
                "historical_dns": {
                    "a_records": [],
                    "aaaa_records": [],
                    "mx_records": [],
                },
                "reverse_ip": {},
                "asn_info": {},
                "tls_cert_info": {
                    "issuer": "",
                    "subject": "",
                    "sans": [],
                    "not_before": "",
                    "not_after": "",
                },
                "dnssec_info": {
                    "dnssec_enabled": False,
                    "spf_record": "",
                    "dmarc_record": "",
                },
                "ip_geolocation": {},
                "breach_info": {"source": "", "breaches": []},
                "port_scan_results": {},
                "web_technologies": {},
                "personnel_info": {"employees": []},
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
                "targeted_industries": ["finance"],
                "known_indicators": ["bad.com"],
            }
        }

    def test_create_stix_bundle_with_all_data_types(self):
        """
        Tests the creation of a STIX bundle with various data types.
        """
        # --- Arrange ---

        all_scans = [
            {"module": "footprint", "result": json.dumps(self.footprint_data)},
            {
                "module": "vulnerability_scanner",
                "result": json.dumps(self.vuln_scan_data),
            },
            {
                "module": "threat_actor_profile",
                "result": json.dumps(self.threat_actor_data),
            },
        ]

        # --- Act ---

        bundle_str = stix_converter.create_stix_bundle("example.com", all_scans)
        bundle_dict = json.loads(bundle_str)
        bundle = Bundle(bundle_dict["objects"])

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
