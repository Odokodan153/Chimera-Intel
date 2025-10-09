import typer
import whois  # type: ignore
import dns.resolver
import asyncio
import re
import shodan  # type: ignore
from rich.panel import Panel
from dotenv import load_dotenv
from typing import Dict, Any, List, Optional
import logging
import time
from httpx import RequestError, HTTPStatusError
from chimera_intel.core.utils import console, save_or_print_results, is_valid_domain
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.config_loader import CONFIG, API_KEYS
from chimera_intel.core.schemas import (
    FootprintResult,
    FootprintData,
    SubdomainReport,
    ScoredResult,
)
from chimera_intel.core.http_client import async_client
from .threat_intel import get_threat_intel_otx
from .project_manager import resolve_target

logger = logging.getLogger(__name__)
load_dotenv()

# --- Simple In-Memory Cache ---


API_CACHE: Dict[str, Any] = {}
CACHE_TTL_SECONDS = 600  # Cache results for 10 minutes


# --- Synchronous Helper Functions ---


def get_whois_info(domain: str) -> Dict[str, Any]:
    """Retrieves WHOIS information for a given domain."""
    try:
        domain_info = whois.whois(domain)
        if domain_info and domain_info.get("domain_name"):
            return dict(domain_info)
        else:
            return {"error": "No WHOIS record found."}
    except Exception as e:
        logger.error(f"An exception occurred during WHOIS lookup for '{domain}': {e}")
        return {"error": f"An exception occurred during WHOIS lookup: {e}"}


def get_dns_records(domain: str) -> Dict[str, Any]:
    """Retrieves common DNS records for a given domain from config.yaml."""
    dns_results: Dict[str, Any] = {}
    record_types = CONFIG.modules.footprint.dns_records_to_query
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            dns_results[record_type] = [str(r.to_text()).strip('"') for r in answers]
        except dns.resolver.NoAnswer:
            dns_results[record_type] = None
        except dns.resolver.NXDOMAIN:
            logger.warning(f"DNS query failed for '{domain}' (NXDOMAIN).")
            return {"error": f"Domain does not exist (NXDOMAIN): {domain}"}
        except Exception as e:
            logger.error(
                f"Could not resolve DNS record type '{record_type}' for '{domain}': {e}"
            )
            dns_results[record_type] = [f"Could not resolve {record_type}: {e}"]
    return dns_results


# --- Asynchronous Data Gathering Functions ---


async def get_subdomains_virustotal(domain: str, api_key: str) -> List[str]:
    """Asynchronously retrieves subdomains from the VirusTotal API."""
    if not api_key:
        return []
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100"

    if (
        url in API_CACHE
        and (time.time() - API_CACHE[url]["timestamp"]) < CACHE_TTL_SECONDS
    ):
        logger.info(f"Returning cached VirusTotal data for {domain}")
        return API_CACHE[url]["data"]
    try:
        response = await async_client.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        subdomains = [item.get("id") for item in data.get("data", [])]
        API_CACHE[url] = {"timestamp": time.time(), "data": subdomains}
        return subdomains
    except (HTTPStatusError, RequestError) as e:
        logger.error(f"Error fetching subdomains from VirusTotal for '{domain}': {e}")
        return []


async def get_subdomains_dnsdumpster(domain: str) -> List[str]:
    """Asynchronously scrapes subdomains from DNSDumpster by handling CSRF tokens."""
    url = "https://dnsdumpster.com/"
    cache_key = f"{url}_{domain}"
    if (
        cache_key in API_CACHE
        and (time.time() - API_CACHE[cache_key]["timestamp"]) < CACHE_TTL_SECONDS
    ):
        logger.info(f"Returning cached DNSDumpster data for {domain}")
        return API_CACHE[cache_key]["data"]
    try:
        home_response = await async_client.get(url)
        home_response.raise_for_status()
        csrf_token = home_response.cookies.get("csrftoken")
        if not csrf_token:
            logger.warning("Could not retrieve CSRF token from DNSDumpster.")
            return []
        post_data = {
            "csrfmiddlewaretoken": csrf_token,
            "targetip": domain,
            "user": "free",
        }
        headers = {"Referer": "https://dnsdumpster.com/"}
        results_response = await async_client.post(url, data=post_data, headers=headers)
        results_response.raise_for_status()
        subdomains_set = set(
            re.findall(
                r'<td class="col-md-4">([\w\d\.\-]+\.' + re.escape(domain) + r")<br>",
                results_response.text,
            )
        )
        subdomains = list(subdomains_set)
        API_CACHE[cache_key] = {"timestamp": time.time(), "data": subdomains}
        return subdomains
    except (HTTPStatusError, RequestError) as e:
        logger.error(f"Error scraping DNSDumpster for '{domain}': {e}")
        return []


async def get_subdomains_threatminer(domain: str) -> List[str]:
    """Asynchronously retrieves subdomains from the ThreatMiner API."""
    url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
    if (
        url in API_CACHE
        and (time.time() - API_CACHE[url]["timestamp"]) < CACHE_TTL_SECONDS
    ):
        logger.info(f"Returning cached ThreatMiner data for {domain}")
        return API_CACHE[url]["data"]
    try:
        response = await async_client.get(url)
        response.raise_for_status()
        data = response.json()
        if data.get("status_code") == "200":
            results = data.get("results", [])
            API_CACHE[url] = {"timestamp": time.time(), "data": results}
            return results
        return []
    except (RequestError, HTTPStatusError) as e:
        logger.error(f"Error fetching subdomains from ThreatMiner for '{domain}': {e}")
        return []


async def get_subdomains_urlscan(domain: str) -> List[str]:
    """Asynchronously retrieves subdomains from the URLScan.io API."""
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    if (
        url in API_CACHE
        and (time.time() - API_CACHE[url]["timestamp"]) < CACHE_TTL_SECONDS
    ):
        logger.info(f"Returning cached URLScan.io data for {domain}")
        return API_CACHE[url]["data"]
    try:
        response = await async_client.get(url)
        response.raise_for_status()
        data = response.json()
        subdomains = {
            result["page"]["domain"]
            for result in data.get("results", [])
            if "page" in result and "domain" in result["page"]
        }
        subdomain_list = list(subdomains)
        API_CACHE[url] = {"timestamp": time.time(), "data": subdomain_list}
        return subdomain_list
    except (RequestError, HTTPStatusError) as e:
        logger.error(f"Error fetching subdomains from URLScan.io for '{domain}': {e}")
        return []


async def get_subdomains_shodan(domain: str, api_key: str) -> List[str]:
    """Asynchronously retrieves subdomains from the Shodan API."""
    if not api_key:
        return []
    query = f"hostname:.{domain}"
    if (
        query in API_CACHE
        and (time.time() - API_CACHE[query]["timestamp"]) < CACHE_TTL_SECONDS
    ):
        logger.info(f"Returning cached Shodan data for {domain}")
        return API_CACHE[query]["data"]

    def search() -> List[str]:
        try:
            api = shodan.Shodan(api_key)
            result = api.search(query, limit=500)
            hostnames = {
                host["hostnames"][0]
                for host in result["matches"]
                if host.get("hostnames")
            }
            hostname_list = list(hostnames)
            API_CACHE[query] = {"timestamp": time.time(), "data": hostname_list}
            return hostname_list
        except Exception as e:
            logger.error(f"Error fetching subdomains from Shodan for '{domain}': {e}")
            return []

    return await asyncio.to_thread(search)


# --- Core Logic Function ---


async def gather_footprint_data(domain: str) -> FootprintResult:
    """
    Orchestrates the gathering of all footprint data.
    """
    # --- Stage 1: Initial Data Gathering ---

    vt_api_key = API_KEYS.virustotal_api_key
    shodan_api_key = API_KEYS.shodan_api_key

    initial_tasks = [
        (
            get_subdomains_virustotal(domain, vt_api_key)
            if vt_api_key
            else asyncio.sleep(0, result=[])
        ),
        get_subdomains_dnsdumpster(domain),
        get_subdomains_threatminer(domain),
        get_subdomains_urlscan(domain),
        (
            get_subdomains_shodan(domain, shodan_api_key)
            if shodan_api_key
            else asyncio.sleep(0, result=[])
        ),
        asyncio.to_thread(get_whois_info, domain),
        asyncio.to_thread(get_dns_records, domain),
    ]
    results = await asyncio.gather(*initial_tasks)
    vt, dd, tm, us, sh, whois_data, dns_data = results

    # --- Stage 2: Consolidate and Prepare for Enrichment ---

    all_subdomains: Dict[str, List[str]] = {}
    if isinstance(vt, list):
        for sub in vt:
            all_subdomains.setdefault(sub, []).append("VirusTotal")
    if isinstance(dd, list):
        for sub in dd:
            all_subdomains.setdefault(sub, []).append("DNSDumpster")
    if isinstance(tm, list):
        for sub in tm:
            all_subdomains.setdefault(sub, []).append("ThreatMiner")
    if isinstance(us, list):
        for sub in us:
            all_subdomains.setdefault(sub, []).append("URLScan.io")
    if isinstance(sh, list):
        for sub in sh:
            all_subdomains.setdefault(sub, []).append("Shodan")
    indicators_to_check = set(all_subdomains.keys())
    main_domain_ips = (
        dns_data.get("A", []) if isinstance(dns_data, dict) and dns_data else []
    )
    for ip in main_domain_ips:
        indicators_to_check.add(ip)
    # --- Stage 3: Threat Intelligence Enrichment ---

    threat_intel_results: Dict[str, Any] = {}
    if API_KEYS.otx_api_key:
        with console.status(
            "[bold cyan]Correlating findings with threat intelligence...[/bold cyan]"
        ):
            threat_intel_tasks = [
                get_threat_intel_otx(indicator) for indicator in indicators_to_check
            ]
            ti_results = await asyncio.gather(*threat_intel_tasks)
            for res in ti_results:
                if res:
                    threat_intel_results[res.indicator] = res
    # --- Stage 4: Final Assembly ---

    available_sources = sum(1 for key in [vt_api_key, shodan_api_key] if key) + 3
    scored_results = [
        ScoredResult(
            domain=sub,
            sources=sources,
            confidence=f"{'HIGH' if len(sources) > 1 else 'LOW'} ({len(sources)}/{available_sources} sources)",
            threat_intel=threat_intel_results.get(sub),
        )
        for sub, sources in sorted(all_subdomains.items())
    ]
    ip_threat_intelligence = [
        threat_intel_results[ip] for ip in main_domain_ips if ip in threat_intel_results
    ]
    subdomain_report = SubdomainReport(
        total_unique=len(scored_results), results=scored_results
    )
    footprint_data = FootprintData(
        whois_info=whois_data if isinstance(whois_data, dict) else {},
        dns_records=dns_data if isinstance(dns_data, dict) else {},
        subdomains=subdomain_report,
        ip_threat_intelligence=ip_threat_intelligence,
    )
    return FootprintResult(domain=domain, footprint=footprint_data)


# Alias for compatibility with aia_framework.py

run_footprint_analysis = gather_footprint_data


# --- Typer CLI Application ---


footprint_app = typer.Typer()

# ... (rest of the file)
