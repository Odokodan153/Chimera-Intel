"""
opsec_footprint.py

This module provides the OpsecFootprint class, which acts as an orchestrator
to simulate an adversary's OSINT process and generate a risk report.
"""

import logging
from typing import Dict, Any

# Import existing modules to be orchestrated
from chimera_intel.core.footprint import Footprint
from chimera_intel.core.personnel_osint import PersonnelOsint
from chimera_intel.core.social_osint import SocialOsint
from chimera_intel.core.cloud_osint import CloudOsint
from chimera_intel.core.reporter import Reporter
from chimera_intel.core.schemas import Organization

log = logging.getLogger(__name__)


class OpsecFootprint:
    """
    Orchestrates various OSINT modules to generate a comprehensive
    Adversary Risk Exposure Report.
    """

    def __init__(self):
        log.info("OpsecFootprint initialized.")
        # Initialize all required modules
        self.footprint = Footprint()
        self.personnel_osint = PersonnelOsint()
        self.social_osint = SocialOsint()
        self.cloud_osint = CloudOsint()
        self.reporter = Reporter()

    def generate_report(self, organization: Organization) -> Dict[str, Any]:
        """
        Runs a full OSINT simulation against the target organization.
        
        Args:
            organization: An Organization schema object containing known
                          assets like name, domains, social handles.

        Returns:
            A dictionary containing the compiled report findings.
        """
        log.info(f"Generating OPSEC Footprint report for: {organization.name}")
        compiled_findings = {
            "summary": "Adversary Risk Exposure Report",
            "target": organization.name,
            "domain_footprint": {},
            "personnel_exposure": {},
            "social_media_presence": {},
            "cloud_exposure": {},
        }

        try:
            # 1. Run domain footprinting
            if organization.domains:
                domain = organization.domains[0]
                # Assuming Footprint class has a scan method
                compiled_findings["domain_footprint"] = self.footprint.scan(domain)
                
                # 2. Run cloud OSINT
                compiled_findings["cloud_exposure"] = self.cloud_osint.scan_domain(domain)
            
            # 3. Run personnel OSINT
            compiled_findings["personnel_exposure"] = self.personnel_osint.scan_organization(organization.name)

            # 4. Run social media OSINT
            if organization.social_media_handles:
                handles = organization.social_media_handles
                compiled_findings["social_media_presence"] = self.social_osint.scan_handles(handles)
            
            log.info("All OSINT modules complete. Compiling report.")

            # 5. Generate a formal report
            report_output = self.reporter.generate_report(
                title=f"Adversary Risk Exposure Report for {organization.name}",
                findings=compiled_findings
            )
            
            compiled_findings["report_path"] = str(report_output)
            return compiled_findings

        except Exception as e:
            log.error(f"Error during OPSEC footprint generation: {e}", exc_info=True)
            return {"error": str(e)}