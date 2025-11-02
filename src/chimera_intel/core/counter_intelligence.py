"""
Advanced defensive counter-intelligence modules.

This module provides functionality for:
- Detecting hostile infrastructure proximal to client assets using Shodan.
- Scoring potential insider threats by fusing public data (code/paste leaks).
- Tracking media manipulation and disinformation provenance using Google Search.
"""

import logging
from typing import Optional, List, Any, Dict
from urllib.parse import urlparse
import io
import datetime

import typer
import shodan  # type: ignore
import imagehash  # type: ignore
from PIL import Image
from bs4 import BeautifulSoup

from chimera_intel.core.schemas import (
    InfraSearchResult,
    InsiderThreatResult,
    MediaProvenanceResult,
    InfraPattern,
    PersonnelRiskScore,
    MediaVector
)
from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.http_client import sync_client
from chimera_intel.core.google_search import search_google
from chimera_intel.core.defensive import search_github_leaks, search_pastes_api

logger = logging.getLogger(__name__)


# --- Threat Actor Infrastructure Methodologies (Shodan Queries) ---
# A real implementation would load this from a dynamic database.
APT_METHODOLOGIES_DB: Dict[str, Dict[str, Any]] = {
    "apt-c2-cobaltstrike": {
        "query": 'ssl.jarm:"07d14d16d21d21d00042d41d000000a450562657b54a7c1340796a5f761a3e"',
        "confidence": 0.8,
        "pattern_name": "Cobalt Strike C2 (JARM)"
    },
    "apt-c2-metasploit": {
        "query": 'http.favicon.hash:-752601742',
        "confidence": 0.6,
        "pattern_name": "Metasploit C2 (Favicon)"
    },
    "open-rdp": {
        "query": 'port:3389 "Authentication: SUCCESSFUL"',
        "confidence": 0.3,
        "pattern_name": "Exposed RDP"
    }
}

# --- Data Gathering & Analysis Functions ---

def search_collection_infrastructure(
    client_asset: str, apt_methodologies: List[str]
) -> InfraSearchResult:
    """
    Searches Shodan for infrastructure patterns matching threat actor methodologies.

    Args:
        client_asset (str): The client's asset (e.g., ASN:AS15169, net:1.2.3.0/24).
        apt_methodologies (List[str]): A list of methodology keys from APT_METHODOLOGIES_DB.

    Returns:
        InfraSearchResult: A Pydantic model with matched patterns, or an error.
    """
    logger.info(f"Starting infrastructure collection scan for asset: {client_asset}")
    api_key = API_KEYS.shodan_api_key
    if not api_key:
        return InfraSearchResult(error="Shodan API key not found.", client_asset=client_asset)
    
    api = shodan.Shodan(api_key)
    matched_patterns = []
    
    for methodology_key in apt_methodologies:
        methodology = APT_METHODOLOGIES_DB.get(methodology_key)
        if not methodology:
            logger.warning(f"Unknown methodology key: {methodology_key}")
            continue
            
        full_query = f'{methodology["query"]} {client_asset}'
        logger.debug(f"Running Shodan query: {full_query}")
        
        try:
            results = api.search(full_query, limit=50)
            for res in results.get("matches", []):
                pattern = InfraPattern(
                    pattern_name=methodology["pattern_name"],
                    provider=res.get("org", "N/A"),
                    indicator=res.get("ip_str", "N/A"),
                    confidence=methodology["confidence"],
                    details={
                        "port": res.get("port"),
                        "asn": res.get("asn"),
                        "hostnames": res.get("hostnames"),
                        "banner": res.get("data", "").strip(),
                    }
                )
                matched_patterns.append(pattern)
        except Exception as e:
            logger.error(f"Error querying Shodan for '{full_query}': {e}")
            return InfraSearchResult(client_asset=client_asset, error=str(e))

    return InfraSearchResult(
        client_asset=client_asset,
        total_found=len(matched_patterns),
        matched_patterns=matched_patterns
    )


def score_insider_threat(
    personnel_ids: List[str], use_internal_signals: bool = False
) -> InsiderThreatResult:
    """
    Fuses public data (GitHub, Pastes) to generate an insider threat risk score.

    Args:
        personnel_ids (List[str]): List of personnel identifiers (e.g., email, username).
        use_internal_signals (bool): Flag (currently placeholder) to enable internal data.

    Returns:
        InsiderThreatResult: A Pydantic model with risk scores for personnel.
    """
    logger.info(f"Starting insider threat scoring for {len(personnel_ids)} personnel.")
    
    github_pat = API_KEYS.github_pat
    scores = []
    high_risk_count = 0
    
    if use_internal_signals:
        logger.warning("Internal signal fusion is not implemented. Using public data only.")

    for pid in personnel_ids:
        risk_score = 0.0
        key_factors = []
        
        # 1. Check for GitHub leaks
        if github_pat:
            logger.debug(f"Checking GitHub for: {pid}")
            gh_query = f'"{pid}"'
            gh_results = search_github_leaks(gh_query, github_pat)
            if gh_results.total_count and gh_results.total_count > 0:
                risk_score += 0.4
                key_factors.append(f"Potential code/credential leak on GitHub ({gh_results.total_count} matches)")
        
        # 2. Check for pastebin leaks
        logger.debug(f"Checking pastes for: {pid}")
        paste_results = search_pastes_api(pid)
        if paste_results.count and paste_results.count > 0:
            risk_score += 0.6  # Pastes are often more explicit leaks
            key_factors.append(f"Potential data leak on Paste.ee ({paste_results.count} pastes)")
        
        # 3. (Placeholder) Check public social media sentiment
        # A real module would use a social_osint_tool here.
        
        risk_score = min(risk_score, 1.0)  # Cap score at 1.0
        
        if risk_score > 0.7:
            high_risk_count += 1
            
        scores.append(PersonnelRiskScore(
            personnel_id=pid,
            risk_score=risk_score,
            key_factors=key_factors if key_factors else ["No public risk factors found"]
        ))
    
    return InsiderThreatResult(
        total_personnel_analyzed=len(personnel_ids),
        high_risk_count=high_risk_count,
        personnel_scores=scores
    )


async def _get_media_fingerprint(url: str) -> tuple[str, str, Optional[str]]:
    """Fetches media and returns (fingerprint, type, error)."""
    try:
        response = await sync_client.get(url, follow_redirects=True, timeout=10)
        response.raise_for_status()
        content_type = response.headers.get("content-type", "").lower()
        
        if "image/" in content_type:
            try:
                img = Image.open(io.BytesIO(response.content))
                fingerprint = str(imagehash.phash(img))
                return fingerprint, "image", None
            except Exception as e:
                return "image_hash_error", "image", f"Failed to hash image: {e}"
        
        elif "text/html" in content_type:
            soup = BeautifulSoup(response.text, "lxml")
            title = soup.find("title").get_text() if soup.find("title") else ""
            # Simple text fingerprint: hash of the title
            fingerprint = f'"{title}"'
            if not title:
                # Fallback: hash of the domain
                fingerprint = f'"{urlparse(url).netloc}"'
            return fingerprint, "article", None
        
        else:
            return "unknown_content_type", "unknown", f"Unsupported content type: {content_type}"
            
    except Exception as e:
        return "fetch_error", "unknown", f"Failed to fetch URL: {e}"


def track_media_manipulation(
    media_url: str,
) -> MediaProvenanceResult:
    """
    Tracks the provenance and spread of a specific media item (image, article, video).

    Args:
        media_url (str): The URL of the media item to track.

    Returns:
        MediaProvenanceResult: A Pydantic model showing the origin and spread.
    """
    import asyncio
    
    logger.info(f"Starting media manipulation tracking for: {media_url}")
    
    # 1. Get media fingerprint
    try:
        fingerprint, media_type, f_error = asyncio.run(_get_media_fingerprint(media_url))
    except Exception as e:
        return MediaProvenanceResult(media_fingerprint="async_error", error=str(e))
        
    if f_error:
        return MediaProvenanceResult(media_fingerprint=fingerprint, media_type=media_type, error=f_error)

    # 2. Search for this fingerprint
    # A real tool would use TinEye API for images and Google News/Web for text.
    # We will use the existing Google Search module as a proxy.
    
    logger.info(f"Searching for fingerprint: {fingerprint} (Type: {media_type})")
    
    # This assumes search_google returns a list of result objects
    try:
        # Note: google_search module needs to be adapted to handle reverse image search
        # For now, we just search for the text/hash.
        if media_type == "image":
            query = f'"{fingerprint}"' # Simulating search by hash
        else: # article
            query = fingerprint
            
        search_results = search_google(query, num_results=20)
    except Exception as e:
        return MediaProvenanceResult(
            media_fingerprint=fingerprint,
            media_type=media_type,
            error=f"Google Search failed: {e}"
        )

    # 3. Analyze and sort results by timestamp (heuristic)
    # This is a major simplification. Real analysis requires scraping timestamps.
    # We will assume search results are somewhat relevance/date-sorted.
    
    vectors = []
    for res in search_results:
        # Heuristic: Try to parse a date from the snippet
        # This is NOT reliable and just for demonstration.
        
        vectors.append(MediaVector(
            platform=urlparse(res.url).netloc,
            identifier=res.url,
            timestamp=None, # A real implementation would scrape this
            snippet=res.snippet
        ))

    origin_vector = vectors[0] if vectors else None
    if origin_vector:
        origin_vector.is_origin = True
        
    return MediaProvenanceResult(
        media_fingerprint=fingerprint,
        media_type=media_type,
        origin_vector=origin_vector,
        spread_path=vectors[1:] if vectors else [],
        confidence=0.4 if vectors else 0.0 # Confidence is low without real timestamps
    )


# --- Typer CLI Application ---

counter_intel_app = typer.Typer()

@counter_intel_app.command("infra-check")
def run_infra_check(
    client_asset: str = typer.Argument(..., help="Client asset (e.g., 'asn:AS15169', 'net:1.2.3.0/24') to check."),
    apt_list: str = typer.Option("apt-c2-cobaltstrike,open-rdp", help="Comma-separated list of APT methodology keys."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """Checks for threat actor infrastructure in your public assets using Shodan."""
    methodologies = [name.strip() for name in apt_list.split(",")]
    results = search_collection_infrastructure(client_asset, methodologies)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(
        target=client_asset, module="counter_intel_infra", data=results.model_dump()
    )

@counter_intel_app.command("insider-score")
def run_insider_score(
    personnel_list: str = typer.Argument(..., help="Comma-separated list of personnel emails or IDs."),
    include_internal: bool = typer.Option(False, "--internal", help="Fuse with internal data sources (placeholder)."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """Generates insider threat risk scores based on public data leaks."""
    personnel_ids = [pid.strip() for pid in personnel_list.split(",")]
    results = score_insider_threat(personnel_ids, include_internal)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(
        target="personnel_batch", module="counter_intel_insider", data=results.model_dump()
    )

@counter_intel_app.command("media-track")
def run_media_track(
    media_url: str = typer.Argument(..., help="URL of the article or image to track."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """Tracks the provenance and spread of a media item for manipulation campaigns."""
    results = track_media_manipulation(media_url)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(
        target=media_url, module="counter_intel_media", data=results.model_dump()
    )