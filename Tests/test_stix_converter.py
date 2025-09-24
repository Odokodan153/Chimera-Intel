import unittest
import json
from chimera_intel.core.stix_converter import (
    convert_footprint_to_stix,
    create_stix_bundle,
    convert_threat_actor_to_stix,
    convert_web_analysis_to_stix,  # Import new function
)
from chimera_intel.core.schemas import (
    FootprintResult,
    FootprintData,
    SubdomainReport,
    ScoredResult,
    ThreatIntelResult,
    ThreatActorIntelResult,
    ThreatActor,
    WebAnalysisResult,  # Import new schema
    WebAnalysisData,
    TechStackReport,
)
from stix2 import Identity  # Import for creating identity object for tests


class TestStixConverter(unittest.TestCase):
    """Test cases for the STIX Converter module."""

    def setUp(self):
        """Create a standard STIX Identity object for use in tests."""
        self.identity = Identity(
            name="example.com",
            identity_class="organization",
        )

    def test_convert_footprint_to_stix(self):
        """Tests the conversion of a FootprintResult to STIX objects."""
        # Arrange

        footprint_data = FootprintResult(
            domain="example.com",
            footprint=FootprintData(
                whois_info={},
                dns_records={"A": ["1.2.3.4"]},
                subdomains=SubdomainReport(
                    total_unique=1,
                    results=[
                        ScoredResult(
                            domain="sub.example.com",
                            confidence="HIGH",
                            sources=["test"],
                        )
                    ],
                ),
                ip_threat_intelligence=[
                    ThreatIntelResult(
                        indicator="1.2.3.4", is_malicious=True, pulse_count=5, pulses=[]
                    )
                ],
            ),
        )

        # Act

        stix_objects = convert_footprint_to_stix(footprint_data, self.identity)

        # Assert

        self.assertGreater(len(stix_objects), 3)
        types = {obj["type"] for obj in stix_objects}
        self.assertIn("ipv4-addr", types)
        self.assertIn("domain-name", types)
        self.assertIn("relationship", types)
        self.assertIn("indicator", types)

    def test_convert_web_analysis_to_stix(self):
        """Tests the conversion of a WebAnalysisResult to STIX objects."""
        # Arrange

        web_analysis_data = WebAnalysisResult(
            domain="example.com",
            web_analysis=WebAnalysisData(
                tech_stack=TechStackReport(
                    total_unique=1,
                    results=[
                        ScoredResult(
                            technology="React", confidence="HIGH", sources=["test"]
                        )
                    ],
                ),
                traffic_info={},
            ),
        )

        # Act

        stix_objects = convert_web_analysis_to_stix(web_analysis_data, self.identity)

        # Assert

        self.assertEqual(len(stix_objects), 2)  # Tool and Relationship
        types = {obj["type"] for obj in stix_objects}
        self.assertIn("tool", types)
        self.assertIn("relationship", types)
        tool_obj = next(obj for obj in stix_objects if obj["type"] == "tool")
        self.assertEqual(tool_obj["name"], "React")

    def test_convert_threat_actor_to_stix(self):
        """Tests the conversion of a ThreatActorIntelResult to STIX objects."""
        # Arrange

        actor_data = ThreatActorIntelResult(
            actor=ThreatActor(
                name="APT28",
                aliases=["Fancy Bear"],
                targeted_industries=["Government", "Defense"],
                known_ttps=[],
                known_indicators=[],
            )
        )
        # Act

        stix_objects = convert_threat_actor_to_stix(actor_data)
        # Assert

        self.assertGreater(len(stix_objects), 3)
        types = {obj["type"] for obj in stix_objects}
        self.assertIn("threat-actor", types)
        self.assertIn("intrusion-set", types)
        self.assertIn("identity", types)
        self.assertIn("relationship", types)

    def test_create_stix_bundle(self):
        """Tests the creation of a full STIX bundle, including the Report object."""
        # Arrange

        scans = [
            {
                "module": "footprint",
                "scan_data": json.dumps(
                    {
                        "domain": "example.com",
                        "footprint": {
                            "whois_info": {},
                            "dns_records": {"A": ["1.2.3.4"]},
                            "subdomains": {"total_unique": 0, "results": []},
                            "ip_threat_intelligence": [],
                        },
                    }
                ),
            }
        ]

        # Act

        bundle_str = create_stix_bundle("example.com", scans)
        bundle = json.loads(bundle_str)

        # Assert

        self.assertEqual(bundle["type"], "bundle")
        self.assertIn("spec_version", bundle)
        self.assertGreater(len(bundle["objects"]), 0)
        # Check for the presence of the main Report object

        self.assertTrue(any(obj["type"] == "report" for obj in bundle["objects"]))


if __name__ == "__main__":
    unittest.main()
