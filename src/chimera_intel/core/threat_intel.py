import logging
from typing import List, Optional
from .schemas import ThreatIntelResult, PulseInfo
from .config_loader import API_KEYS
from .http_client import async_client

logger = logging.getLogger(__name__)


async def get_threat_intel_otx(indicator: str) -> Optional[ThreatIntelResult]:
    """
    Retrieves threat intelligence for a given indicator (IP, domain) from AlienVault OTX.

    Args:
        indicator (str): The indicator to look up (e.g., '8.8.8.8' or 'google.com').

    Returns:
        Optional[ThreatIntelResult]: A Pydantic model with the threat intel context,
                                     or None if the API key is not configured.
    """
    api_key = API_KEYS.otx_api_key
    if not api_key:
        return None  # Skip if no API key is provided
    # Determine the correct OTX API endpoint based on the indicator type

    indicator_type = ""
    if "/" in indicator:  # Simple check for URL or path
        return None  # OTX does not handle full URLs well, skip for now
    elif "." in indicator:
        # Could be an IP or a domain

        try:
            # Check if it's an IP address

            parts = indicator.split(".")
            if len(parts) == 4 and all(part.isdigit() for part in parts):
                indicator_type = "IPv4"
            else:
                indicator_type = "domain"
        except:
            indicator_type = "hostname"
    else:  # It's not an IP or a domain we can easily classify
        return ThreatIntelResult(
            indicator=indicator, is_malicious=False, error="Unsupported indicator type"
        )
    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
    headers = {"X-OTX-API-KEY": api_key}

    try:
        response = await async_client.get(url, headers=headers)

        # OTX returns 404 if the indicator is unknown, which is not an error for us

        if response.status_code == 404:
            return ThreatIntelResult(indicator=indicator, is_malicious=False)
        response.raise_for_status()
        data = response.json()

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        is_malicious = pulse_count > 0

        pulses = [
            PulseInfo(
                name=p.get("name"),
                malware_families=[mf for mf in p.get("malware_families", [])],
                tags=p.get("tags", []),
            )
            for p in data.get("pulse_info", {}).get("pulses", [])
        ]

        return ThreatIntelResult(
            indicator=indicator,
            pulse_count=pulse_count,
            is_malicious=is_malicious,
            pulses=pulses,
        )
    except Exception as e:
        logger.error("Error querying OTX for indicator '%s': %s", indicator, e)
        return ThreatIntelResult(
            indicator=indicator, error=f"An OTX API error occurred: {e}"
        )
