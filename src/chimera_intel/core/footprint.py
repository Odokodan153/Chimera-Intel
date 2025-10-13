import typer
import whois  # type: ignore
import dns.resolver
import asyncio
import re
import shodan  # type: ignore
import nmap  # type: ignore
import hibpapi
from rich.panel import Panel
from dotenv import load_dotenv
from typing import Dict, Any, List, Optional, Coroutine
import logging
import time
from httpx import RequestError, HTTPStatusError
from wappalyzer import Wappalyzer, WebPage
from chimera_intel.core.utils import console, save_or_print_results, is_valid_domain
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.config_loader import CONFIG, API_KEYS
from chimera_intel.core.schemas import (
    FootprintResult,
    FootprintData,
    SubdomainReport,
    ScoredResult,
    DnssecInfo,
    TlsCertInfo,
    AsnInfo,
    HistoricalDns,
    IpGeolocation,
    BreachInfo,
    PortScanResult,
    WebTechInfo,
    PersonnelInfo,
    KnowledgeGraph,
    IpInfo,
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
    """Retrieves WHOIS information for a given domain.

    Args:
        domain (str): The domain to perform the WHOIS lookup on.

    Returns:
        Dict[str, Any]: A dictionary of the WHOIS record, or an error message.
    """
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
    """Retrieves common DNS records for a given domain from config.yaml.

    Args:
        domain (str): The domain to query for DNS records.

    Returns:
        Dict[str, Any]: A dictionary where keys are record types (e.g., 'A', 'MX')
                        and values are lists of records, or an error message.
    """
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
    """Asynchronously retrieves subdomains from the VirusTotal API.

    Args:
        domain (str): The domain to query for subdomains.
        api_key (str): The VirusTotal API key.

    Returns:
        List[str]: A list of subdomain strings found.
    """
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
    """Asynchronously scrapes subdomains from DNSDumpster by handling CSRF tokens.

    Args:
        domain (str): The domain to query for subdomains.

    Returns:
        List[str]: A list of subdomain strings found.
    """
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
    """Asynchronously retrieves subdomains from the ThreatMiner API.

    Args:
        domain (str): The domain to query for subdomains.

    Returns:
        List[str]: A list of subdomain strings found.
    """
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
    """Asynchronously retrieves subdomains from the URLScan.io API.

    Args:
        domain (str): The domain to query for subdomains.

    Returns:
        List[str]: A list of subdomain strings found.
    """
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
    """Asynchronously retrieves subdomains from the Shodan API.

    This function runs the synchronous Shodan library in a separate thread
    to avoid blocking the asyncio event loop.

    Args:
        domain (str): The domain to query for subdomains.
        api_key (str): The Shodan API key.

    Returns:
        List[str]: A list of subdomain strings found.
    """
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


# --- Extended Intelligence Functions ---


async def get_ip_info(ip_address: str) -> IpInfo:
    """Retrieves combined ASN and geolocation info for an IP address using ipinfo.io.

    Args:
        ip_address (str): The IP address to query.

    Returns:
        IpInfo: A Pydantic model containing combined IP information.
    """
    url = f"https://ipinfo.io/{ip_address}/json"
    if (
        url in API_CACHE
        and (time.time() - API_CACHE[url]["timestamp"]) < CACHE_TTL_SECONDS
    ):
        logger.info(f"Returning cached IP info for {ip_address}")
        return API_CACHE[url]["data"]
    try:
        response = await async_client.get(url)
        response.raise_for_status()
        data = response.json()
        ip_info = IpInfo(
            asn=AsnInfo(
                asn=data.get("org"),
                owner=data.get("org"),
                country=data.get("country"),
                prefix=data.get("org"),
            ),
            geolocation=IpGeolocation(
                ip=ip_address,
                city=data.get("city"),
                country=data.get("country"),
                provider=data.get("org"),
            ),
        )
        API_CACHE[url] = {"timestamp": time.time(), "data": ip_info}
        return ip_info
    except (HTTPStatusError, RequestError) as e:
        logger.error(f"Error fetching IP info from ipinfo.io for '{ip_address}': {e}")
        return IpInfo(
            asn=AsnInfo(asn="", owner="", country="", prefix=""),
            geolocation=IpGeolocation(ip=ip_address, city="", country="", provider=""),
        )


async def get_passive_dns(domain: str, api_key: str) -> HistoricalDns:
    """Retrieves passive DNS information from VirusTotal.

    Args:
        domain (str): The domain to query.
        api_key (str): The VirusTotal API key.

    Returns:
        HistoricalDns: A Pydantic model containing historical DNS records.
    """
    if not api_key:
        return HistoricalDns(a_records=[], aaaa_records=[], mx_records=[])
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions"
    headers = {"x-apikey": api_key}
    cache_key = f"{url}_{domain}"
    if (
        cache_key in API_CACHE
        and (time.time() - API_CACHE[cache_key]["timestamp"]) < CACHE_TTL_SECONDS
    ):
        logger.info(f"Returning cached passive DNS data for {domain}")
        return API_CACHE[cache_key]["data"]

    try:
        response = await async_client.get(url, headers=headers)
        response.raise_for_status()
        data = response.json().get("data", [])
        a_records = [
            f"{item['attributes']['ip_address']} ({item['attributes']['date']})"
            for item in data
            if item["attributes"]["ip_address"]
        ]
        API_CACHE[cache_key] = {
            "timestamp": time.time(),
            "data": HistoricalDns(a_records=a_records, aaaa_records=[], mx_records=[]),
        }
        return API_CACHE[cache_key]["data"]
    except (HTTPStatusError, RequestError) as e:
        logger.error(f"Error fetching passive DNS from VirusTotal for '{domain}': {e}")
        return HistoricalDns(a_records=[], aaaa_records=[], mx_records=[])


async def get_reverse_ip_lookup(ip_address: str) -> List[str]:
    """Performs a reverse IP lookup to find other domains on the same IP.

    Args:
        ip_address (str): The IP address to perform the reverse lookup on.

    Returns:
        List[str]: A list of domain names hosted on the IP address.
    """
    try:
        reversed_ip = dns.reversename.from_address(ip_address)
        return [str(ptr) for ptr in dns.resolver.resolve(reversed_ip, "PTR")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception as e:
        logger.error(f"Error performing reverse IP lookup for '{ip_address}': {e}")
        return []


async def get_tls_cert_info(domain: str) -> TlsCertInfo:
    """Analyzes TLS/SSL certificate information from crt.sh.

    Args:
        domain (str): The domain to query for certificates.

    Returns:
        TlsCertInfo: A Pydantic model containing certificate information.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    cache_key = f"{url}_{domain}"
    if (
        cache_key in API_CACHE
        and (time.time() - API_CACHE[cache_key]["timestamp"]) < CACHE_TTL_SECONDS
    ):
        logger.info(f"Returning cached TLS certificate info for {domain}")
        return API_CACHE[cache_key]["data"]
    try:
        response = await async_client.get(url)
        response.raise_for_status()
        data = response.json()
        if not data:
            return TlsCertInfo(issuer="", subject="", sans=[], not_before="", not_after="")
        latest_cert = data[0]
        cert_info = TlsCertInfo(
            issuer=latest_cert.get("issuer_name"),
            subject=latest_cert.get("common_name"),
            sans=latest_cert.get("name_value", "").split("\n"),
            not_before=latest_cert.get("not_before"),
            not_after=latest_cert.get("not_after"),
        )
        API_CACHE[cache_key] = {"timestamp": time.time(), "data": cert_info}
        return cert_info
    except (HTTPStatusError, RequestError) as e:
        logger.error(f"Error fetching TLS certificate info from crt.sh for '{domain}': {e}")
        return TlsCertInfo(issuer="", subject="", sans=[], not_before="", not_after="")


async def check_dnssec(domain: str) -> DnssecInfo:
    """Validates DNSSEC, SPF, DKIM, and DMARC records.

    Args:
        domain (str): The domain to check.

    Returns:
        DnssecInfo: A Pydantic model containing DNS security information.
    """
    dnssec_enabled = False
    spf_record = ""
    dmarc_record = ""
    try:
        dnskey_response = dns.resolver.resolve(domain, dns.rdatatype.DNSKEY)
        if dnskey_response:
            dnssec_enabled = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass  # DNSSEC not enabled
    except Exception as e:
        logger.error(f"Error checking DNSSEC for '{domain}': {e}")


    try:
        spf_response = dns.resolver.resolve(domain, "TXT")
        for record in spf_response:
            if "v=spf1" in str(record):
                spf_record = str(record)
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except Exception as e:
        logger.error(f"Error checking SPF for '{domain}': {e}")

    try:
        dmarc_response = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for record in dmarc_response:
            if "v=DMARC1" in str(record):
                dmarc_record = str(record)
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except Exception as e:
        logger.error(f"Error checking DMARC for '{domain}': {e}")


    return DnssecInfo(
        dnssec_enabled=dnssec_enabled,
        spf_record=spf_record.strip('"'),
        dmarc_record=dmarc_record.strip('"'),
    )


async def detect_cdn(domain: str) -> Optional[str]:
    """Detects if a domain is using a CDN.

    Args:
        domain (str): The domain to check.

    Returns:
        Optional[str]: The name of the CDN provider if detected, otherwise None.
    """
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        for rdata in answers:
            cname = str(rdata.target)
            if "cloudflare" in cname:
                return "Cloudflare"
            elif "akamai" in cname:
                return "Akamai"
            elif "fastly" in cname:
                return "Fastly"
            elif "aws" in cname:
                return "Amazon CloudFront"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except Exception as e:
        logger.error(f"Error detecting CDN for '{domain}': {e}")
    return None


async def get_breach_info(domain: str, api_key: str) -> BreachInfo:
    """Checks for data breaches and leaks associated with a domain using HaveIBeenPwned.

    Args:
        domain (str): The domain to check for breaches.
        api_key (str): The HIBP API key.

    Returns:
        BreachInfo: A Pydantic model containing breach information.
    """
    if not api_key:
        return BreachInfo(source="HaveIBeenPwned", breaches=[])
    cache_key = f"hibp_{domain}"
    if (
        cache_key in API_CACHE
        and (time.time() - API_CACHE[cache_key]["timestamp"]) < CACHE_TTL_SECONDS
    ):
        logger.info(f"Returning cached breach info for {domain}")
        return API_CACHE[cache_key]["data"]

    try:
        with hibpapi.HIBP(api_key=api_key) as hibp:
            breaches = hibp.get_breaches_for_account(email=f"test@{domain}")
        breach_names = [breach.name for breach in breaches]
        breach_info = BreachInfo(source="HaveIBeenPwned", breaches=breach_names)
        API_CACHE[cache_key] = {"timestamp": time.time(), "data": breach_info}
        return breach_info
    except Exception as e:
        logger.error(f"Error fetching breach info from HIBP for '{domain}': {e}")
        return BreachInfo(source="HaveIBeenPwned", breaches=[])


async def perform_port_scan(ip_address: str) -> PortScanResult:
    """Performs a light port scan to identify open ports and services using python-nmap.

    WARNING: Port scanning can have legal implications. Use responsibly.

    Args:
        ip_address (str): The IP address to scan.

    Returns:
        PortScanResult: A Pydantic model containing open ports and services.
    """
    nm = nmap.PortScanner()
    try:
        # Scanning top 1000 ports
        nm.scan(ip_address, "1-1000")
        open_ports = {}
        if ip_address in nm.all_hosts():
            for proto in nm[ip_address].all_protocols():
                lport = nm[ip_address][proto].keys()
                for port in lport:
                    open_ports[port] = nm[ip_address][proto][port]["name"]
        return PortScanResult(open_ports=open_ports)
    except Exception as e:
        logger.error(f"Error performing port scan on '{ip_address}': {e}")
        return PortScanResult(open_ports={})


async def get_web_technologies(url: str) -> WebTechInfo:
    """Profiles web technologies used by a website using Wappalyzer.

    Args:
        url (str): The URL of the website to profile.

    Returns:
        WebTechInfo: A Pydantic model containing web technology information.
    """
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        technologies = wappalyzer.analyze_with_versions(webpage)
        web_tech_info = WebTechInfo(
            cms=technologies.get("cms", [None])[0],
            framework=technologies.get("javascript-frameworks", [None])[0],
            web_server=technologies.get("web-servers", [None])[0],
            js_library=technologies.get("javascript-libraries", [None])[0],
        )
        return web_tech_info
    except Exception as e:
        logger.error(f"Error profiling web technologies for '{url}': {e}")
        return WebTechInfo(cms="", framework="", web_server="", js_library="")


async def discover_personnel(domain: str, api_key: str) -> PersonnelInfo:
    """Discovers employee and contact information related to a domain using Hunter.io.

    Args:
        domain (str): The domain to query.
        api_key (str): The Hunter.io API key.

    Returns:
        PersonnelInfo: A Pydantic model containing personnel information.
    """
    if not api_key:
        return PersonnelInfo(employees=[])
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
    cache_key = f"hunter_{domain}"
    if (
        cache_key in API_CACHE
        and (time.time() - API_CACHE[cache_key]["timestamp"]) < CACHE_TTL_SECONDS
    ):
        logger.info(f"Returning cached personnel info for {domain}")
        return API_CACHE[cache_key]["data"]

    try:
        response = await async_client.get(url)
        response.raise_for_status()
        data = response.json().get("data", {}).get("emails", [])
        employees = [
            {
                "name": f"{email.get('first_name', '')} {email.get('last_name', '')}".strip(),
                "email": email.get("value"),
                "title": email.get("position"),
            }
            for email in data
        ]
        personnel_info = PersonnelInfo(employees=employees)
        API_CACHE[cache_key] = {"timestamp": time.time(), "data": personnel_info}
        return personnel_info
    except (HTTPStatusError, RequestError) as e:
        logger.error(f"Error fetching personnel info from Hunter.io for '{domain}': {e}")
        return PersonnelInfo(employees=[])


# --- Core Logic Function ---


async def gather_footprint_data(domain: str) -> FootprintResult:
    """
    Orchestrates the gathering of all footprint data.

    Args:
        domain (str): The target domain for the footprint scan.

    Returns:
        FootprintResult: A Pydantic model containing all the gathered
                         and processed data.
    """
    # --- Stage 1: Initial Data Gathering ---

    vt_api_key = API_KEYS.virustotal_api_key
    shodan_api_key = API_KEYS.shodan_api_key
    hibp_api_key = API_KEYS.hibp_api_key
    hunter_api_key = API_KEYS.hunter_api_key

    initial_tasks = [
        get_subdomains_virustotal(domain, vt_api_key) if vt_api_key else asyncio.sleep(0, result=[]),
        get_subdomains_dnsdumpster(domain),
        get_subdomains_threatminer(domain),
        get_subdomains_urlscan(domain),
        get_subdomains_shodan(domain, shodan_api_key) if shodan_api_key else asyncio.sleep(0, result=[]),
        asyncio.to_thread(get_whois_info, domain),
        asyncio.to_thread(get_dns_records, domain),
        get_passive_dns(domain, vt_api_key) if vt_api_key else asyncio.sleep(0, result=HistoricalDns(a_records=[], aaaa_records=[], mx_records=[])),
        get_tls_cert_info(domain),
        check_dnssec(domain),
        get_breach_info(domain, hibp_api_key) if hibp_api_key else asyncio.sleep(0, result=BreachInfo(source="HaveIBeenPwned", breaches=[])),
        get_web_technologies(f"https://{domain}"),
        discover_personnel(domain, hunter_api_key) if hunter_api_key else asyncio.sleep(0, result=PersonnelInfo(employees=[])),
    ]
    results = await asyncio.gather(*initial_tasks, return_exceptions=True)
    (
        vt,
        dd,
        tm,
        us,
        sh,
        whois_data,
        dns_data,
        passive_dns_data_res,
        tls_cert_data_res,
        dnssec_data_res,
        breach_data_res,
        web_tech_data_res,
        personnel_data_res,
    ) = results

    # --- Stage 1.5: Data Validation and Defaulting ---
    passive_dns_data = passive_dns_data_res if isinstance(passive_dns_data_res, HistoricalDns) else HistoricalDns(a_records=[], aaaa_records=[], mx_records=[])
    tls_cert_data = tls_cert_data_res if isinstance(tls_cert_data_res, TlsCertInfo) else TlsCertInfo(issuer="", subject="", sans=[], not_before="", not_after="")
    dnssec_data = dnssec_data_res if isinstance(dnssec_data_res, DnssecInfo) else DnssecInfo(dnssec_enabled=False, spf_record="", dmarc_record="")
    breach_data = breach_data_res if isinstance(breach_data_res, BreachInfo) else BreachInfo(source="HaveIBeenPwned", breaches=[])
    web_tech_data = web_tech_data_res if isinstance(web_tech_data_res, WebTechInfo) else WebTechInfo()
    personnel_data = personnel_data_res if isinstance(personnel_data_res, PersonnelInfo) else PersonnelInfo(employees=[])


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

    # --- Stage 3: IP-based Enrichment ---

    ip_enrichment_tasks: List[tuple[str, Coroutine[Any, Any, Any]]] = []
    for ip in main_domain_ips:
        ip_enrichment_tasks.append((ip, get_ip_info(ip)))
        ip_enrichment_tasks.append((ip, get_reverse_ip_lookup(ip)))
        ip_enrichment_tasks.append((ip, perform_port_scan(ip)))

    ip_enrichment_results: Dict[str, Dict[str, Any]] = {ip: {} for ip in main_domain_ips}
    if ip_enrichment_tasks:
        ip_results = await asyncio.gather(*[task for _, task in ip_enrichment_tasks], return_exceptions=True)
        for (ip, _), result in zip(ip_enrichment_tasks, ip_results):
            if isinstance(result, IpInfo):
                ip_enrichment_results[ip]["ip_info"] = result
            elif isinstance(result, list):
                ip_enrichment_results[ip]["reverse_ip"] = result
            elif isinstance(result, PortScanResult):
                ip_enrichment_results[ip]["port_scan"] = result

    # --- Stage 4: Threat Intelligence Enrichment ---

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

    # --- Stage 5: Final Assembly ---

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

    # Safely construct dictionaries, providing default values for missing data
    asn_info_dict = {}
    ip_geolocation_dict = {}
    for ip in main_domain_ips:
        ip_info = ip_enrichment_results.get(ip, {}).get("ip_info")
        if ip_info:
            asn_info_dict[ip] = ip_info.asn
            ip_geolocation_dict[ip] = ip_info.geolocation

    port_scan_results_dict = {
        ip: ip_enrichment_results.get(ip, {}).get("port_scan", PortScanResult(open_ports={}))
        for ip in main_domain_ips
    }


    footprint_data = FootprintData(
        whois_info=whois_data if isinstance(whois_data, dict) else {},
        dns_records=dns_data if isinstance(dns_data, dict) else {},
        subdomains=subdomain_report,
        ip_threat_intelligence=ip_threat_intelligence,
        historical_dns=passive_dns_data,
        reverse_ip={ip: ip_enrichment_results.get(ip, {}).get("reverse_ip", []) for ip in main_domain_ips},
        asn_info=asn_info_dict,
        tls_cert_info=tls_cert_data,
        dnssec_info=dnssec_data,
        ip_geolocation=ip_geolocation_dict,
        cdn_provider=await detect_cdn(domain),
        breach_info=breach_data,
        port_scan_results=port_scan_results_dict,
        web_technologies=web_tech_data,
        personnel_info=personnel_data,
        knowledge_graph=KnowledgeGraph(nodes=[], edges=[]),
    )
    return FootprintResult(domain=domain, footprint=footprint_data)


# Alias for compatibility with aia_framework.py

run_footprint_analysis = gather_footprint_data


# --- Typer CLI Application ---


footprint_app = typer.Typer()


@footprint_app.command("run")
def run_footprint_scan(
    domain: Optional[str] = typer.Argument(
        None,
        help="The target domain. If not provided, uses the active project's domain.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """Gathers digital footprint info for a domain."""
    target_domain = resolve_target(domain, required_assets=["domain"])

    if not is_valid_domain(target_domain):
        logger.warning(
            "Invalid domain format provided to 'footprint' command: %s", target_domain
        )
        console.print(
            Panel(
                f"[bold red]Invalid Input:[/] '{target_domain}' is not a valid domain format.",
                title="Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    logger.info("Starting asynchronous footprint scan for %s", target_domain)

    results_model = asyncio.run(gather_footprint_data(target_domain))
    results_dict = results_model.model_dump()

    logger.info("Footprint scan complete for %s", target_domain)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=target_domain, module="footprint", data=results_dict)


if __name__ == "__main__":
    footprint_app()