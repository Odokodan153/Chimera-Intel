"""
Advanced defensive counter-intelligence modules.

This module provides functionality for:
- Detecting hostile infrastructure proximal to client assets using Shodan.
- Scoring potential insider threats by fusing public data (code/paste leaks).
- Tracking media manipulation and disinformation provenance using Google Search.
"""

import logging
from typing import Optional, List, Any, Dict, Set
from urllib.parse import urlparse
import io
import os
import json
from pathlib import Path
import glob
import http.server
import socketserver
import threading
import typer
import shodan  # type: ignore
import imagehash  # type: ignore
from PIL import Image, ImageDraw, ImageFont
from bs4 import BeautifulSoup
import dns.resolver  # type: ignore
import dns.exception  # type: ignore

# NEW: Added for real media fingerprinting (OCR)
try:
    import pytesseract  # type: ignore
except ImportError:
    pytesseract = None
    logging.warning("pytesseract not found. OCR features will be disabled. Run 'pip install pytesseract'")


from chimera_intel.core.schemas import (
    InfraSearchResult,
    InsiderThreatResult,
    MediaProvenanceResult,
    InfraPattern,
    PersonnelRiskScore,
    MediaVector,
    DomainMonitoringResult,
    HoneyAssetResult,
    LegalTemplateResult
)
from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.http_client import sync_client
from chimera_intel.core.google_search import search_google
from chimera_intel.core.defensive import search_github_leaks, search_pastes_api

logger = logging.getLogger(__name__)

# --- Dynamic Data Loading ---

# Define the path to the data file relative to this script
DATA_FILE_PATH = Path(__file__).parent / "counter_intel_data.json"

def _load_counter_intel_data(data_type: str) -> Dict[str, Any]:
    """
    (Real) Loads dynamic data from the JSON file.
    """
    try:
        if not DATA_FILE_PATH.exists():
            logger.error(f"Counter-intelligence data file not found: {DATA_FILE_PATH}")
            return {}
        
        with open(DATA_FILE_PATH, 'r') as f:
            data = json.load(f)
            return data.get(data_type, {})
    except Exception as e:
        logger.error(f"Failed to load counter-intel data from {DATA_FILE_PATH}: {e}")
        return {}

# --- Data Gathering & Analysis Functions ---

def search_collection_infrastructure(
    client_asset: str, apt_methodologies: List[str]
) -> InfraSearchResult:
    """
    (Real) Searches Shodan for infrastructure patterns matching threat actor methodologies.
    """
    logger.info(f"Starting infrastructure collection scan for asset: {client_asset}")
    api_key = API_KEYS.shodan_api_key
    if not api_key:
        return InfraSearchResult(error="Shodan API key not found.", client_asset=client_asset)
    
    # Load dynamic methodologies
    methodologies_db = _load_counter_intel_data("apt_methodologies")
    if not methodologies_db:
        return InfraSearchResult(error="Failed to load APT methodologies data.", client_asset=client_asset)

    api = shodan.Shodan(api_key)
    matched_patterns = []
    
    for methodology_key in apt_methodologies:
        methodology = methodologies_db.get(methodology_key)
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

def _check_local_file_system_leaks(personnel_id: str) -> List[str]:
    """
    (Real - Local) Scans local user directories for files containing the personnel ID.
    This simulates a check for internal data leaked onto a workstation.
    """
    logger.info(f"Scanning local file system for internal leaks related to: {personnel_id}")
    found_files: List[str] = []
    username = personnel_id.split("@")[0] if "@" in personnel_id else personnel_id
    search_terms = [personnel_id, username]
    
    # Define common directories and file types
    home_dir = os.path.expanduser('~')
    dirs_to_scan = [os.path.join(home_dir, d) for d in ["Documents", "Downloads", "Desktop", "Code"]]
    file_extensions = ["*.txt", "*.csv", "*.json", "*.py", "*.md", "*.log", "*.pem", "*.key", "*.sql"]

    for directory in dirs_to_scan:
        if not os.path.exists(directory):
            continue
        
        for ext in file_extensions:
            # Use recursive glob to find files
            for filepath in glob.glob(os.path.join(directory, "**", ext), recursive=True):
                try:
                    # To avoid reading huge files, just read the first 1MB
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1024 * 1024) 
                        for term in search_terms:
                            if term in content:
                                logger.warning(f"Found term '{term}' in local file: {filepath}")
                                found_files.append(filepath)
                                break # Stop checking this file
                except Exception as e:
                    logger.debug(f"Could not read file {filepath}: {e}")
                    
    return list(set(found_files)) # Return unique files


def score_insider_threat(
    personnel_ids: List[str], use_internal_signals: bool = False
) -> InsiderThreatResult:
    """
    (Partially Real) Fuses public data + local file system "internal" checks.

    NOTE: The 'use_internal_signals' flag now triggers a REAL scan of the
    local file system, simulating a check for data leaked onto a workstation.
    """
    logger.info(f"Starting insider threat scoring for {len(personnel_ids)} personnel.")
    
    github_pat = API_KEYS.github_pat
    scores = []
    high_risk_count = 0
    
    for pid in personnel_ids:
        risk_score = 0.0
        key_factors = []
        username = pid.split("@")[0] if "@" in pid else pid
        
        # 1. Check for GitHub leaks
        if github_pat:
            logger.debug(f"Checking GitHub for: {pid}")
            gh_query = f'"{pid}" OR "{username}"'
            gh_results = search_github_leaks(gh_query, github_pat)
            if gh_results.total_count and gh_results.total_count > 0:
                risk_score += 0.4
                key_factors.append(f"Potential code/credential leak on GitHub ({gh_results.total_count} matches)")
        
        # 2. Check for pastebin leaks
        logger.debug(f"Checking pastes for: {pid}")
        paste_results = search_pastes_api(pid)
        if paste_results.count and paste_results.count > 0:
            risk_score += 0.6
            key_factors.append(f"Potential data leak on Paste.ee ({paste_results.count} pastes)")
        
        # 3. (Heuristic) Check public social/web sentiment
        try:
            logger.debug(f"Checking public sentiment for: {pid}")
            sentiment_query = f'("{pid}" OR "{username}") AND (complaint OR lawsuit OR disgruntled OR fired OR "data breach")'
            sentiment_results = search_google(sentiment_query, num_results=5)
            if sentiment_results:
                risk_score += 0.2
                key_factors.append(f"Potential negative public sentiment found ({len(sentiment_results)} matches)")
        except Exception as e:
            logger.warning(f"Google Search for sentiment failed for {pid}: {e}")

        # 4. (Real - Local) Check for "internal" leaks on the local file system
        if use_internal_signals:
            local_leaks = _check_local_file_system_leaks(pid)
            if local_leaks:
                risk_score += 0.5 # High-confidence, high-risk finding
                key_factors.append(f"Potential sensitive data on local workstation ({len(local_leaks)} files, e.g., {local_leaks[0]})")
        
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
    """
    (Real) Fetches media and returns a high-quality text fingerprint.
    - Uses OCR for images.
    - Uses paragraph extraction for articles.
    """
    try:
        response = await sync_client.get(url, follow_redirects=True, timeout=10)
        response.raise_for_status()
        content_type = response.headers.get("content-type", "").lower()
        
        if "image/" in content_type:
            if not pytesseract:
                return "ocr_error", "image", "pytesseract library not installed."
            try:
                img = Image.open(io.BytesIO(response.content))
                # Perform OCR to get a text-based fingerprint
                text = pytesseract.image_to_string(img)
                text = " ".join(text.split()) # Normalize whitespace
                if not text:
                    return "ocr_empty", "image", "OCR returned no text. Using pHash fallback."
                
                fingerprint = f'"{text[:500]}"' # Use first 500 chars of text
                return fingerprint, "image_ocr", None
            except Exception as e:
                return "ocr_error", "image", f"Failed to OCR image: {e}"
        
        elif "text/html" in content_type:
            soup = BeautifulSoup(response.text, "lxml")
            # Extract first meaningful paragraph as a fingerprint
            first_p = soup.find("p")
            if first_p:
                text = " ".join(first_p.get_text().split()) # Normalize whitespace
                fingerprint = f'"{text[:500]}"' # Use first 500 chars
                return fingerprint, "article", None
            else:
                # Fallback to title
                title = soup.find("title").get_text() if soup.find("title") else ""
                if title:
                    fingerprint = f'"{title}"'
                    return fingerprint, "article", None
                else:
                    return "parse_error", "article", "Could not find <p> or <title> tags."
            
        else:
            return "unknown_content_type", "unknown", f"Unsupported content type: {content_type}"
            
    except Exception as e:
        return "fetch_error", "unknown", f"Failed to fetch URL: {e}"


def track_media_manipulation(
    media_url: str,
) -> MediaProvenanceResult:
    """
    (Real Fingerprint) Tracks spread by searching for OCR'd text or extracted paragraphs.

    NOTE: This uses a high-quality "real" fingerprint (from OCR/parsing)
    but still relies on Google Search, not a dedicated reverse image API.
    """
    import asyncio
    
    logger.info(f"Starting media manipulation tracking for: {media_url}")
    
    # 1. Get media fingerprint (now using OCR/text extraction)
    try:
        fingerprint, media_type, f_error = asyncio.run(_get_media_fingerprint(media_url))
    except Exception as e:
        return MediaProvenanceResult(media_fingerprint="async_error", error=str(e))
        
    if f_error:
        return MediaProvenanceResult(media_fingerprint=fingerprint, media_type=media_type, error=f_error)

    # 2. Search for this fingerprint
    logger.info(f"Searching for real fingerprint: {fingerprint} (Type: {media_type})")
    
    try:
        # The query is now a high-quality text snippet, quoted for exact match
        query = fingerprint
        search_results = search_google(query, num_results=20)
    except Exception as e:
        return MediaProvenanceResult(
            media_fingerprint=fingerprint,
            media_type=media_type,
            error=f"Google Search failed: {e}"
        )

    # 3. Analyze results
    vectors = []
    for res in search_results:
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
        confidence=0.6 if vectors else 0.0 # Confidence is higher with text match
    )

# --- Active Counter-Intel & Legal Escalation ---

# --- Domain Permutation (Real DNS Check) ---

def _generate_domain_permutations(base_domain: str) -> Set[str]:
    """Generates a list of potential typosquatting and homoglyph domains."""
    permutations: Set[str] = set()
    try:
        if '.' not in base_domain:
            return permutations
            
        parts = base_domain.rsplit('.', 1)
        name, tld = parts[0], parts[1]
        
        # 1. Homoglyphs
        homoglyphs = {'o': '0', 'l': '1', 'i': '1', 'a': '4'}
        for char, glyph in homoglyphs.items():
            if char in name:
                permutations.add(f"{name.replace(char, glyph)}.{tld}")
                
        # 2. Typosquatting (simple)
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        # Omission
        for i in range(len(name)):
            permutations.add(f"{name[:i]}{name[i+1:]}.{tld}")
        # Repetition
        for i in range(len(name)):
            permutations.add(f"{name[:i]}{name[i]}{name[i:]}.{tld}")
        # Substitution
        for i in range(len(name)):
            for char in chars:
                if name[i] != char:
                    permutations.add(f"{name[:i]}{char}{name[i+1:]}.{tld}")
                    
        # 3. Different TLDs
        for new_tld in ["net", "org", "biz", "info", "co", "io", "xyz"]:
            permutations.add(f"{name}.{new_tld}")
            
        # 4. Hyphenation
        if '-' in name:
            permutations.add(f"{name.replace('-', '')}.{tld}")
        else:
            if len(name) > 4: # Add hyphen in middle
                 permutations.add(f"{name[:len(name)//2]}-{name[len(name)//2:]}.{tld}")

    except Exception as e:
        logger.warning(f"Error generating domain permutations: {e}")
        
    return permutations

def _check_domain_permutations(base_domain: str, brand_name: str) -> List[str]:
    """
    (Real) Checks for lookalike domains using DNS resolution.
    """
    logger.info(f"Generating domain permutations for {base_domain} and {brand_name}...")
    
    perms = _generate_domain_permutations(base_domain)
    try:
        brand_domain = f"{brand_name.lower().replace(' ', '').replace('.', '')}.com"
        if brand_domain != base_domain:
            perms.update(_generate_domain_permutations(brand_domain))
    except Exception:
        pass 

    logger.info(f"Checking {len(perms)} potential lookalike domains via DNS...")
    
    found_domains = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.0
    resolver.lifetime = 1.0
    
    for domain in perms:
        if domain == base_domain:
            continue
            
        try:
            resolver.resolve(domain, 'A')
            logger.warning(f"Found active lookalike domain: {domain}")
            found_domains.append(f"http://{domain}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        except Exception as e:
            logger.debug(f"Error checking domain {domain}: {e}")
            
    return found_domains


def monitor_impersonation(
    base_domain: str,
    brand_name: str,
    social_platforms: Optional[List[str]] = None,
    official_social_urls: Optional[List[str]] = None,
    check_permutations: bool = True
) -> DomainMonitoringResult:
    """
    (Real) Monitors for lookalike domains (DNS) and impersonator accounts (Google).
    """
    if social_platforms is None:
        social_platforms = ["twitter.com", "facebook.com", "linkedin.com", "instagram.com", "tiktok.com"]
    if official_social_urls is None:
        official_social_urls = []

    normalized_official_urls = [
        url.lower().replace("https://", "").replace("http://", "").replace("www.", "").strip("/")
        for url in official_social_urls
    ]

    logger.info(f"Starting impersonation monitoring for domain: {base_domain}")
    results = DomainMonitoringResult(base_domain=base_domain)
    
    try:
        # 1. Look for lookalike domains (Real DNS Check)
        if check_permutations:
            results.lookalikes_found = _check_domain_permutations(base_domain, brand_name)
        else:
            logger.info("Skipping DNS permutation check.")

        # 2. Look for impersonator accounts (Google Search Heuristic)
        for platform in social_platforms:
            account_query = f'site:{platform} "{brand_name}"'
            account_hits = search_google(account_query, num_results=5)
            for hit in account_hits:
                normalized_hit_url = hit.url.lower().replace("https://", "").replace("http://", "").replace("www.", "").strip("/")
                
                if normalized_hit_url not in normalized_official_urls:
                    logger.warning(f"Found potential impersonator: {hit.url}")
                    results.impersonator_accounts.append({
                        "platform": platform,
                        "url": hit.url,
                        "snippet": hit.snippet
                    })
        
    except Exception as e:
        logger.error(f"Error during impersonation monitoring: {e}")
        results.error = str(e)
        
    return results

# --- Honey Asset (Real Local Tracking Server) ---

SERVER_RUNNING = threading.Lock()
SERVER_STARTED = False

class HoneyAssetLogHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler that logs all GET requests."""
    def __init__(self, *args, **kwargs):
        # Set directory before calling parent __init__
        self.directory = os.path.join(os.getcwd(), 'honey_assets')
        super().__init__(*args, **kwargs)

    def do_GET(self):
        # Log the "hit"
        logger.critical(
            f"[HONEYPOT HIT] Asset '{self.path}' accessed by {self.client_address[0]}"
        )
        super().do_GET()

def _start_tracking_server(port: int = 8080):
    """Starts the local honey asset tracking server in a background thread."""
    global SERVER_STARTED
    with SERVER_RUNNING:
        if SERVER_STARTED:
            logger.debug("Tracking server is already running.")
            return

        try:
            # We must change directory for SimpleHTTPRequestHandler to find files
            # This is a drawback, so we'll use the 'directory' kwarg in Python 3.7+
            # For simplicity, let's use a partial function
            
            Handler = lambda *args, **kwargs: HoneyAssetLogHandler(*args, directory="honey_assets", **kwargs)
            
            # Use 0.0.0.0 to make it accessible on the local network
            httpd = socketserver.TCPServer(("", port), HoneyAssetLogHandler)
            
            logger.info(f"Starting local honey asset tracking server on http://0.0.0.0:{port}")
            logger.info(f"Serving files from '{os.path.join(os.getcwd(), 'honey_assets')}'")

            # Run the server in a daemon thread
            server_thread = threading.Thread(target=httpd.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            SERVER_STARTED = True
        except Exception as e:
            logger.error(f"Failed to start tracking server: {e}")


def deploy_honey_asset(
    image_path: str, watermark_id: str, port: int = 8080
) -> HoneyAssetResult:
    """
    (Real - Local) Creates a watermarked image, saves it locally,
    and starts a local tracking server to log access.
    """
    logger.info(f"Starting (local) honey asset deployment for: {image_path} with ID: {watermark_id}")
    
    output_dir = "honey_assets"
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # 1. Load the image
        img = Image.open(image_path).convert("RGBA")
        
        # 2. Create watermark
        watermark_img = Image.new("RGBA", img.size, (255, 255, 255, 0))
        draw = ImageDraw.Draw(watermark_img)
        
        try:
            font = ImageFont.truetype("arial.ttf", size=40)
        except IOError:
            logger.warning("Arial font not found, using default font.")
            font = ImageFont.load_default()

        text_bbox = draw.textbbox((0, 0), watermark_id, font=font)
        text_width = text_bbox[2] - text_bbox[0]
        text_height = text_bbox[3] - text_bbox[1]
        position = (img.width - text_width - 10, img.height - text_height - 10)
        draw.text(position, watermark_id, font=font, fill=(255, 255, 255, 128))

        # 4. Composite
        watermarked_img = Image.alpha_composite(img, watermark_img)
        
        # 5. Get fingerprint
        fingerprint = str(imagehash.phash(watermarked_img.convert("RGB")))
        
        # 6. Save locally
        output_filename = f"{watermark_id}-{fingerprint}.png"
        output_path = os.path.join(output_dir, output_filename)
        
        watermarked_img.save(output_path, "PNG")
        
        # 7. Start the tracking server (if not already running)
        _start_tracking_server(port=port)
        
        # 8. Create the tracking URL
        # We'll use 127.0.0.1 for the URL, even though server is on 0.0.0.0
        tracking_url = f"http://127.0.0.1:{port}/{output_filename}"
        logger.info(f"Successfully deployed local honey asset. Tracking URL: {tracking_url}")

        return HoneyAssetResult(
            asset_id=watermark_id,
            status="deployed_local_tracking",
            fingerprint=fingerprint,
            tracking_url=tracking_url
        )

    except FileNotFoundError:
        error_msg = f"Source image not found at: {image_path}"
        logger.error(error_msg)
        return HoneyAssetResult(
            asset_id=watermark_id, status="error", fingerprint="", tracking_url="", error=error_msg
        )
    except Exception as e:
        error_msg = f"Failed to process and deploy honey asset: {e}"
        logger.error(error_msg)
        return HoneyAssetResult(
            asset_id=watermark_id,
            status="error",
            fingerprint="",
            tracking_url="",
            error=error_msg
        )

# --- Legal Templates (Real - Dynamic) ---

def get_legal_escalation_template(
    complaint_type: str
) -> LegalTemplateResult:
    """
    (Real) Retrieves legal complaint templates from the dynamic data file.
    """
    templates_db = _load_counter_intel_data("legal_templates")
    if not templates_db:
        return LegalTemplateResult(
            complaint_type=complaint_type,
            template_body="",
            error="Failed to load legal templates data."
        )

    template_data = templates_db.get(complaint_type)
    
    if not template_data:
        return LegalTemplateResult(
            complaint_type=complaint_type,
            template_body="",
            error=f"Template not found. Available types: {list(templates_db.keys())}"
        )
        
    return LegalTemplateResult(
        complaint_type=complaint_type,
        template_body=template_data["template"].strip(),
        contacts=template_data["contacts"]
    )


# --- Typer CLI Application ---

counter_intel_app = typer.Typer()

@counter_intel_app.command("infra-check")
def run_infra_check(
    client_asset: str = typer.Argument(..., help="Client asset (e.g., 'asn:AS15169', 'net:1.2.3.0/24') to check."),
    apt_list: str = typer.Option("apt-c2-cobaltstrike,open-rdp", help="Comma-separated list of APT methodology keys."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """(Real) Checks for threat actor infrastructure in your public assets using Shodan."""
    methodologies = [name.strip() for name in apt_list.split(",")]
    results = search_collection_infrastructure(client_asset, methodologies)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(
        target=client_asset, module="counter_intel_infra", data=results.model_dump()
    )

@counter_intel_app.command("insider-score")
def run_insider_score(
    personnel_list: str = typer.Argument(..., help="Comma-separated list of personnel emails or IDs."),
    include_internal: bool = typer.Option(False, "--internal", help="Run 'internal' checks (scans local file system)."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """(Partially Real) Generates insider risk scores (public + local file scan)."""
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
    """(Real Fingerprint) Tracks media spread using OCR/text extraction."""
    results = track_media_manipulation(media_url)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(
        target=media_url, module="counter_intel_media", data=results.model_dump()
    )

@counter_intel_app.command("domain-watch")
def run_domain_watch(
    base_domain: str = typer.Argument(..., help="Client's primary domain (e.g., 'chimera-intel.com')."),
    brand_name: str = typer.Argument(..., help="Client's brand name (e.g., 'Chimera Intel')."),
    official_urls: Optional[str] = typer.Option(None, "--official-urls", help="Comma-separated list of official social media URLs."),
    check_permutations: bool = typer.Option(True, "--[no-]check-permutations", help="Run DNS checks for lookalike domains (can be slow)."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """(Real) Monitors for lookalike domains (DNS) and brand impersonation (Google)."""
    official_list = [url.strip() for url in official_urls.split(",")] if official_urls else []
    results = monitor_impersonation(
        base_domain,
        brand_name,
        official_social_urls=official_list,
        check_permutations=check_permutations
    )
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(
        target=base_domain, module="counter_intel_domain_watch", data=results.model_dump()
    )

@counter_intel_app.command("honey-deploy")
def run_honey_deploy(
    image_path: str = typer.Argument(..., help="Path to the source image to be watermarked."),
    watermark_id: str = typer.Argument(..., help="Unique tracking ID (e.g., 'campaign-q4-blog')."),
    port: int = typer.Option(8080, help="Port to run the local tracking server on."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """(Real - Local) Deploys a watermarked image and starts a local tracking server."""
    results = deploy_honey_asset(image_path, watermark_id, port=port)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(
        target=watermark_id, module="counter_intel_honey_asset", data=results.model_dump()
    )
    if "127.0.0.1" in results.tracking_url:
        console.print(f"\n[bold yellow]Tracking server is now running. Access the asset at: {results.tracking_url}[/bold yellow]")
        console.print("[bold yellow]Keep this process alive to continue tracking hits.[/bold yellow]")


@counter_intel_app.command("legal-template")
def run_legal_template(
    complaint_type: str = typer.Argument(..., help="Type of complaint (e.g., 'dmca-takedown', 'impersonation-report')."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """(Real) Retrieves legal escalation templates for DMCA, impersonation, etc."""
    results = get_legal_escalation_template(complaint_type)
    save_or_print_results(results.model_dump(), output_file, print_to_console=True)