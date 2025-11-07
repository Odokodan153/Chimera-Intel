"""
MLint Data Clients & Interfaces
(Updated for central config, retry logic, and PEP client)
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import httpx  # Modern async HTTP client
import logging
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential, RetryError # <-- For Retries

from mlint_schemas import SanctionHit, UboInfo, PepHit # <-- Import PepHit
from mlint_config import settings # <-- PHASE 1: Use central config

# Configure logging
log = logging.getLogger(__name__)

# --- Sanctions Client Interface (Req A1) ---

class AbstractSanctionsClient(ABC):
    @abstractmethod
    async def check_entity(self, name: str, entity_type: str) -> List[SanctionHit]:
        """Check an entity name against sanctions lists."""
        pass

class RefinitivSanctionsClient(AbstractSanctionsClient):
    """
    REAL implementation for Refinitiv World-Check.
    This performs actual API calls.
    """
    def __init__(self):
        self.api_key = settings.refinitiv_api_key
        self.base_url = "https://api.refinitiv.com/world-check"
        if not self.api_key:
            log.warning("REFINITIV_API_KEY not set in config. Sanctions client will return no results.")
        
        # Use httpx.AsyncClient for connection pooling and performance
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=10.0
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)) # <-- New Retry
    async def check_entity(self, name: str, entity_type: str) -> List[SanctionHit]:
        if not self.api_key:
            return []
        
        # --- REAL IMPLEMENTATION ---
        api_payload = {
            "entity": {
                "name": name,
                "type": entity_type.upper() # e.g., 'PERSON' or 'ORGANISATION'
            },
            "screeningConfiguration": {
                "matchThreshold": "HIGH" # Example config
            }
        }
        
        try:
            response = await self.client.post("/v2/screening", json=api_payload)
            response.raise_for_status()  # Raise an exception for 4xx/5xx errors
            return self._parse_results(response.json())
        except httpx.HTTPStatusError as e:
            log.error(f"HTTP error checking sanctions for '{name}': {e}")
            raise # Re-raise to trigger retry
        except httpx.RequestError as e:
            log.error(f"Network error checking sanctions for '{name}': {e}")
            raise # Re-raise to trigger retry
        except Exception as e:
            log.error(f"Error parsing sanctions response for '{name}': {e}")
            
        return []

    def _parse_results(self, api_response: Dict[str, Any]) -> List[SanctionHit]:
        # This parsing is specific to the World-Check API format
        hits = []
        for result in api_response.get("results", []):
            for match in result.get("matches", []):
                hits.append(SanctionHit(
                    source_list=match.get("sourceList", "World-Check"),
                    entity_name=match.get("matchedName"),
                    match_score=match.get("matchStrength", 0.0),
                    details=match.get("details", {})
                ))
        return hits

# --- UBO Client Interface (Req A2) ---

class AbstractUboClient(ABC):
    @abstractmethod
    async def get_ubo(self, company_name: str, jurisdiction: str) -> Optional[UboInfo]:
        """Fetch Ultimate Beneficial Owner data."""
        pass

class OpenCorporatesClient(AbstractUboClient):
    """
    REAL implementation for OpenCorporates (Req A2).
    """
    def __init__(self):
        self.api_key = settings.open_corporates_api_key
        self.base_url = "https.api.opencorporates.com"
        if not self.api_key:
            log.warning("OPEN_CORPORATES_API_KEY not set in config. UBO client will return no results.")
        
        self.client = httpx.AsyncClient(
            base_url=f"https://{self.base_url}",
            params={"api_token": self.api_key},
            timeout=10.0
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)) # <-- New Retry
    async def get_ubo(self, company_name: str, jurisdiction: str) -> Optional[UboInfo]:
        if not self.api_key:
            return None
            
        # --- REAL IMPLEMENTATION ---
        # This is a 2-step process: 1. Search company, 2. Get UBOs
        try:
            # 1. Search for the company
            search_params = {"q": company_name, "jurisdiction_code": jurisdiction}
            search_resp = await self.client.get("/v0.4/companies/search", params=search_params)
            search_resp.raise_for_status()
            companies = search_resp.json().get("results", {}).get("companies", [])
            
            if not companies:
                log.info(f"No OpenCorporates company found for '{company_name}' in '{jurisdiction}'")
                return None
            
            # Assume first result is the best match
            company_data = companies[0].get("company", {})
            company_api_url = company_data.get("opencorporates_url")

            # 2. Fetch UBO / Officer data (this part is complex and API-dependent)
            # OpenCorporates UBO data is often in 'statements' or 'officers'
            # This is a simplified example; real UBO data is hard to get.
            officers_resp = await self.client.get(f"/v0.4/companies/{company_data['jurisdiction_code']}/{company_data['company_number']}/officers")
            officers_data = officers_resp.json().get("results", {}).get("officers", [])
            
            for officer_entry in officers_data:
                officer = officer_entry.get("officer", {})
                if "beneficial owner" in officer.get("position", "").lower():
                    return UboInfo(
                        company_name=company_data.get("name"),
                        ubo_name=officer.get("name"),
                        confidence_score=0.7, # Example confidence
                        source="OpenCorporates (Officer List)"
                    )
            
            log.info(f"No UBO found for '{company_name}', returning first officer as example.")
            if officers_data:
                 officer = officers_data[0].get("officer", {})
                 return UboInfo(
                        company_name=company_data.get("name"),
                        ubo_name=officer.get("name"),
                        confidence_score=0.3, # Low confidence (Req A2)
                        source="OpenCorporates (Officer List - Not UBO)"
                    )

        except httpx.HTTPStatusError as e:
            log.error(f"HTTP error fetching UBO for '{company_name}': {e}")
            raise # Re-raise to trigger retry
        except Exception as e:
            log.error(f"Error parsing UBO response for '{company_name}': {e}")
            
        return None

# --- Chain Analysis Client Interface (for Crypto) ---

class AbstractChainAnalysisClient(ABC):
    @abstractmethod
    async def get_wallet_risk(self, wallet_address: str) -> Dict[str, Any]:
        """Get risk score and metadata for a crypto wallet."""
        pass

class ChainalysisClient(AbstractChainAnalysisClient):
    """
    REAL implementation for a chain analysis provider.
    """
    def __init__(self):
        self.api_key = settings.chainalysis_api_key
        self.base_url = "https://api.chainalysis.com/v1"
        if not self.api_key:
            log.warning("CHAINALYSIS_API_KEY not set in config. Chain analysis client will return no results.")
        
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Token {self.api_key}", "Accept": "application/json"},
            timeout=10.0
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)) # <-- New Retry
    async def get_wallet_risk(self, wallet_address: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"risk_score": 0.0, "sources": [], "error": "API key not set"}
            
        # --- REAL IMPLEMENTATION ---
        try:
            # Example endpoint; the real one will vary.
            response = await self.client.get(f"/address/{wallet_address}")
            response.raise_for_status()
            
            data = response.json()
            
            # Parse the provider-specific response into our format
            risk_score = self._normalize_risk(data.get("risk"))
            sources = [category.get("name") for category in data.get("exposures", [])]
            
            return {
                "risk_score": risk_score,
                "sources": sources,
                "cluster_id": data.get("cluster", {}).get("id")
            }
            
        except httpx.HTTPStatusError as e:
            log.error(f"HTTP error fetching wallet risk for '{wallet_address}': {e}")
            raise # Re-raise to trigger retry
        except Exception as e:
            log.error(f"Error parsing wallet risk for '{wallet_address}': {e}")
            return {"risk_score": 0.0, "sources": [], "error": str(e)}

    def _normalize_risk(self, risk_data: Optional[str]) -> float:
        """Converts a provider's risk (e.g., 'HIGH') to a 0-1 score."""
        if not risk_data:
            return 0.0
        risk_data = risk_data.lower()
        if risk_data == "critical":
            return 1.0
        elif risk_data == "high":
            return 0.8
        elif risk_data == "medium":
            return 0.5
        elif risk_data == "low":
            return 0.1
        return 0.0


# --- PEP Client Interface (New) ---

class AbstractPepClient(ABC):
    @abstractmethod
    async def check_entity_pep(self, name: str) -> List[PepHit]:
        """Check an entity name against PEP lists."""
        pass

class OpenSanctionsPepClient(AbstractPepClient):
    """
    REAL implementation for OpenSanctions PEP list.
    """
    def __init__(self):
        # OpenSanctions is free but rate-limited.
        self.base_url = "https://api.opensanctions.org"
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=10.0)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def check_entity_pep(self, name: str) -> List[PepHit]:
        log.info(f"Checking PEP status for {name} via OpenSanctions")
        try:
            # Using the /match endpoint for the 'pep' dataset
            params = {
                "q": name,
                "dataset": "pep",
                "schema": "Person"
            }
            response = await self.client.get("/match", params=params)
            response.raise_for_status()
            
            api_response = response.json()
            hits = []
            for result in api_response.get("results", []):
                hits.append(PepHit(
                    name=result.get("name"),
                    position=result.get("properties", {}).get("position", ["Unknown Position"])[0],
                    country=result.get("properties", {}).get("country", ["zz"])[0],
                    source_url=result.get("links", {}).get("ui", result.get("id"))
                ))
            return hits
            
        except httpx.HTTPStatusError as e:
            log.error(f"HTTP error checking PEP for '{name}': {e}")
            raise # Trigger retry
        except Exception as e:
            log.error(f"Error parsing PEP response for '{name}': {e}")
        
        return []