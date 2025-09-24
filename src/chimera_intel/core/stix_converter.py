"""
Module for converting Chimera Intel's internal data formats to the STIX 2.1 standard.

This module provides the core logic for mapping the platform's Pydantic schemas
to STIX Cyber-Observable Objects (SCOs) and STIX Domain Objects (SDOs), enabling
interoperability with other threat intelligence platforms like MISP.
"""

import logging
from typing import Dict, Any, List
import json
from stix2 import (
    Indicator,
    Identity,
    Relationship,
    DomainName,
    IPv4Address,
    Bundle,
    Vulnerability,
    Tool,
    ThreatActor as StixThreatActor,
    IntrusionSet,
    AttackPattern,
    Report,
)
from datetime import datetime

from .schemas import (
    FootprintResult,
    VulnerabilityScanResult,
    ThreatActorIntelResult,
    WebAnalysisResult,
)
from .database import save_scan_to_db

logger = logging.getLogger(__name__)


def convert_footprint_to_stix(
    footprint: FootprintResult, identity: Identity
) -> List[Any]:
    """
    Converts a FootprintResult into a list of STIX 2.1 objects.
    """
    stix_objects = []
    domain_obj = DomainName(value=footprint.domain)
    stix_objects.append(domain_obj)
    stix_objects.append(Relationship(identity, "owns", domain_obj))

    if footprint.footprint.dns_records.get("A"):
        for ip_str in footprint.footprint.dns_records["A"]:
            ip_obj = IPv4Address(value=ip_str)
            stix_objects.append(ip_obj)
            stix_objects.append(Relationship(domain_obj, "resolves-to", ip_obj))
    for sub_result in footprint.footprint.subdomains.results:
        if sub_result.domain:
            subdomain_obj = DomainName(value=sub_result.domain)
            stix_objects.append(subdomain_obj)
            stix_objects.append(
                Relationship(domain_obj, "has-subdomain", subdomain_obj)
            )
    for ip_intel in footprint.footprint.ip_threat_intelligence:
        if ip_intel.is_malicious:
            indicator = Indicator(
                pattern_type="stix",
                pattern=f"[ipv4-addr:value = '{ip_intel.indicator}']",
                valid_from=datetime.utcnow(),
                description=f"Malicious IP. Pulses: {ip_intel.pulse_count}",
            )
            stix_objects.append(indicator)
    return stix_objects


def convert_web_analysis_to_stix(
    web_analysis: WebAnalysisResult, identity: Identity
) -> List[Any]:
    """Converts a WebAnalysisResult into a list of STIX 2.1 objects."""
    stix_objects = []

    for tech in web_analysis.web_analysis.tech_stack.results:
        # Represent technologies as STIX 'Tool' objects

        tool = Tool(name=tech.technology)
        stix_objects.append(tool)
        stix_objects.append(Relationship(identity, "uses", tool))
    return stix_objects


def convert_vulns_to_stix(
    vuln_scan: VulnerabilityScanResult, identity: Identity
) -> List[Any]:
    """
    Converts a VulnerabilityScanResult into a list of STIX 2.1 objects.
    """
    stix_objects = []
    nmap_tool = Tool(name="Nmap", description="Network mapping and port scanning tool.")
    stix_objects.append(nmap_tool)

    for host_scan in vuln_scan.scanned_hosts:
        host_observable = (
            IPv4Address(value=host_scan.host)
            if all(c.isdigit() or c == "." for c in host_scan.host)
            else DomainName(value=host_scan.host)
        )
        stix_objects.append(host_observable)
        stix_objects.append(Relationship(identity, "owns", host_observable))

        for port in host_scan.open_ports:
            for cve in port.vulnerabilities:
                vulnerability = Vulnerability(
                    name=cve.id,
                    description=cve.title,
                    external_references=[{"source_name": "cve", "external_id": cve.id}],
                )
                stix_objects.append(vulnerability)
                stix_objects.append(Relationship(host_observable, "has", vulnerability))
    return stix_objects


def convert_threat_actor_to_stix(actor_intel: ThreatActorIntelResult) -> List[Any]:
    """
    Converts a ThreatActorIntelResult into a list of STIX 2.1 objects.
    """
    if not actor_intel.actor:
        return []
    actor = actor_intel.actor
    stix_objects = []

    threat_actor = StixThreatActor(name=actor.name, aliases=actor.aliases)
    stix_objects.append(threat_actor)

    intrusion_set = IntrusionSet(name=actor.name, aliases=actor.aliases)
    stix_objects.append(intrusion_set)
    stix_objects.append(Relationship(intrusion_set, "attributed-to", threat_actor))

    for industry in actor.targeted_industries:
        industry_identity = Identity(name=industry, identity_class="class")
        stix_objects.append(industry_identity)
        stix_objects.append(Relationship(intrusion_set, "targets", industry_identity))
    for ttp in actor.known_ttps:
        attack_pattern = AttackPattern(
            name=ttp.description,
            external_references=[
                {"source_name": "mitre-attack", "external_id": ttp.technique_id}
            ],
        )
        stix_objects.append(attack_pattern)
        stix_objects.append(Relationship(intrusion_set, "uses", attack_pattern))
    for ioc in actor.known_indicators:
        pattern = (
            f"[ipv4-addr:value = '{ioc}']"
            if all(c.isdigit() or c == "." for c in ioc)
            else f"[domain-name:value = '{ioc}']"
        )
        indicator = Indicator(pattern_type="stix", pattern=pattern)
        stix_objects.append(indicator)
        stix_objects.append(Relationship(indicator, "indicates", intrusion_set))
    return stix_objects


def create_stix_bundle(target: str, all_scans: List[Dict[str, Any]]) -> str:
    """
    Aggregates all scan data for a target and creates a STIX 2.1 Bundle.
    """
    all_stix_objects: Dict[str, Any] = {}
    identity = Identity(name=target, identity_class="organization")
    all_stix_objects[identity.id] = identity

    report_object_refs = [identity.id]

    for scan in all_scans:
        module = scan.get("module")
        data = json.loads(scan.get("scan_data", "{}"))
        stix_objects = []

        if module == "footprint":
            stix_objects = convert_footprint_to_stix(FootprintResult(**data), identity)
        elif module == "web_analyzer":
            stix_objects = convert_web_analysis_to_stix(
                WebAnalysisResult(**data), identity
            )
        elif module == "vulnerability_scanner":
            stix_objects = convert_vulns_to_stix(
                VulnerabilityScanResult(**data), identity
            )
        elif module == "threat_actor_profile":
            stix_objects = convert_threat_actor_to_stix(ThreatActorIntelResult(**data))
        for obj in stix_objects:
            if obj.id not in all_stix_objects:
                all_stix_objects[obj.id] = obj
                report_object_refs.append(obj.id)
    if len(all_stix_objects) <= 1:
        logger.warning(f"No STIX-convertible data found for target '{target}'.")
        return "{}"
    # Create a STIX Report to contextualize the findings

    report = Report(
        name=f"Chimera Intel Report for {target}",
        published=datetime.utcnow(),
        object_refs=report_object_refs,
    )
    all_stix_objects[report.id] = report

    bundle = Bundle(list(all_stix_objects.values()), allow_custom=True)
    return bundle.serialize(pretty=True)


def import_stix_bundle(file_path: str, project_id: int, user_id: int):
    """
    Imports a STIX 2.1 bundle and saves the intelligence to the database.
    This is a simplified example; a real implementation would be more robust.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        for obj in bundle.get("objects", []):
            if obj.get("type") == "indicator":
                # Create a simplified "scan" from the STIX data to save it

                scan_data = {
                    "stix_id": obj.get("id"),
                    "pattern": obj.get("pattern"),
                    "description": obj.get("description"),
                    "source": "STIX Import",
                }
                # Use the pattern as the "target" for simplicity

                target = obj.get("pattern", "stix_indicator")
                save_scan_to_db(target, "stix_import", scan_data, user_id, project_id)
        return {
            "status": "success",
            "message": f"Successfully imported {len(bundle.get('objects', []))} STIX objects.",
        }
    except Exception as e:
        logger.error(f"Failed to import STIX bundle from {file_path}: {e}")
        return {"status": "error", "message": str(e)}
