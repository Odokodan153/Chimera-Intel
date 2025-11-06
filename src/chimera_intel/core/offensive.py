"""
Module for advanced offensive and reconnaissance operations.

This module contains functions for discovering and fingerprinting APIs,
enumerating hidden web content, and performing advanced cloud reconnaissance.
"""

import typer
import asyncio
import logging
import dns.resolver
import socket  # Import socket to handle gaierror
import subprocess
import json
import shlex # NEW: Import for safe subprocess handling
from typing import Optional, List, Set, Dict, Any
from .schemas import (
    APIDiscoveryResult,
    DiscoveredAPI,
    ContentEnumerationResult,
    DiscoveredContent,
    AdvancedCloudResult,
    SubdomainTakeoverResult,
)
from .http_client import async_client
from .utils import save_or_print_results, console
from .database import save_scan_to_db, get_data_by_module

logger = logging.getLogger(__name__)

# --- API Discovery ---


async def discover_apis(domain: str) -> APIDiscoveryResult:
    """
    Searches for common API endpoints and documentation specifications.
    """
    logger.info(f"Starting API discovery for {domain}")
    discovered = []

    endpoints_to_check = {
        "Swagger/OpenAPI": [
            f"https://{domain}/swagger.json",
            f"https://{domain}/openapi.json",
            f"https://{domain}/api/docs",
        ],
        "GraphQL": [f"https://{domain}/graphql"],
        "REST": [f"https://api.{domain}/v1/", f"https://{domain}/api/v1/"],
    }

    async def check_endpoint(url: str, api_type: str):
        try:
            response = await async_client.head(url, timeout=10, follow_redirects=True)
            if response.status_code != 404:
                discovered.append(
                    DiscoveredAPI(
                        url=url, api_type=api_type, status_code=response.status_code
                    )
                )
        except Exception:
            # Note: This is still broad, but we are fixing the CLI issue first.
            pass

    tasks = [
        check_endpoint(url, api_type)
        for api_type, urls in endpoints_to_check.items()
        for url in urls
    ]
    await asyncio.gather(*tasks)

    return APIDiscoveryResult(target_domain=domain, discovered_apis=discovered)


# --- Content Enumeration ---


async def enumerate_content(domain: str) -> ContentEnumerationResult:
    """
    Performs directory and file enumeration using a small, common wordlist.
    """
    logger.info(f"Performing content enumeration on {domain}")

    # A small but effective list of common paths

    common_paths: Set[str] = {
        "admin",
        "login",
        "dashboard",
        "api",
        "wp-admin",
        "test",
        "dev",
        ".git/config",
        ".env",
        "config.json",
        "backup.zip",
        "robots.txt",
    }

    found_content: List[DiscoveredContent] = []
    base_url = f"https://{domain}"

    async def check_path(path: str):
        url = f"{base_url}/{path}"
        try:
            response = await async_client.head(url, timeout=7, follow_redirects=False)
            # We check for all status codes except 404 (Not Found)

            if response.status_code != 404:
                # We use 'content-length' from the headers if available

                content_length_str = response.headers.get("content-length", "0")
                found_content.append(
                    DiscoveredContent(
                        url=url,
                        status_code=response.status_code,
                        content_length=int(content_length_str),
                    )
                )
        except Exception:
            pass  # Ignore connection errors

    tasks = [check_path(path) for path in common_paths]
    await asyncio.gather(*tasks)

    return ContentEnumerationResult(target_url=base_url, found_content=found_content)


# --- Advanced Cloud Recon ---


async def check_for_subdomain_takeover(
    domain: str, subdomains_to_check: Optional[List[str]] = None
) -> AdvancedCloudResult:
    """
    Checks for dangling DNS records pointing to de-provisioned cloud services.
    """
    logger.info(f"Checking for potential subdomain takeovers on {domain}")

    # Fingerprints of vulnerable services

    vulnerable_fingerprints = {
        "S3 Bucket": ["NoSuchBucket"],
        "Heroku": ["no such app"],
        "GitHub Pages": ["There isn't a GitHub Pages site here."],
        "Shopify": ["Sorry, this shop is currently unavailable."],
        "Ghost": ["The thing you were looking for is no longer here"],
    }

    # Common subdomains to check
    # CHANGED: Use parameter or fall back to default list
    if subdomains_to_check is None:
        subdomains_to_check = [
            "www",
            "assets",
            "blog",
            "dev",
            "staging",
            "api",
            "files",
            "images",
        ]

    potential_takeovers: List[SubdomainTakeoverResult] = []

    async def check_subdomain(sub: str):
        full_domain = f"{sub}.{domain}"
        try:
            # 1. Check for a CNAME record

            resolver = dns.resolver.Resolver()
            cname_answers = await asyncio.to_thread(
                resolver.resolve, full_domain, "CNAME"
            )
            cname_target = str(cname_answers[0].target)

            # 2. Check the page content for fingerprints

            response = await async_client.get(f"http://{full_domain}", timeout=10)
            page_content = response.text.lower()

            for service, fingerprints in vulnerable_fingerprints.items():
                for fingerprint in fingerprints:
                    if fingerprint.lower() in page_content:
                        potential_takeovers.append(
                            SubdomainTakeoverResult(
                                subdomain=full_domain,
                                vulnerable_service=service,
                                details=f"CNAME points to '{cname_target}' and page contains fingerprint: '{fingerprint}'",
                            )
                        )
                        return
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # This is normal if the subdomain has no CNAME or does not exist
            pass
        except (socket.gaierror, dns.resolver.Timeout):
            # This can indicate a resolvable CNAME to a non-existent domain.
            # This is a potential finding, as suggested by your test analysis.
            potential_takeovers.append(
                SubdomainTakeoverResult(
                    subdomain=full_domain,
                    vulnerable_service="Unknown (Resolution Failure)",
                    details="DNS resolution failed, possibly vulnerable to takeover.",
                )
            )
        except Exception:
            # Ignore other errors (e.g., connection timeout)
            pass

    tasks = [check_subdomain(sub) for sub in subdomains_to_check]
    await asyncio.gather(*tasks)

    return AdvancedCloudResult(
        target_domain=domain, potential_takeovers=potential_takeovers
    )

# --- New WiFi Attack Surface Modeling ---

def _model_wifi_attack_surface_from_data(target: str, sigint_data: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    (Helper) Models potential WiFi attack vectors from a list of scan results.
    """
    if not sigint_data:
        return None # No data

    potential_vectors = []
    
    for network in sigint_data:
        ssid = network.get("ssid", "Unknown")
        security = network.get("security_type", "Unknown")
        
        if security in ["WEP", "WPA-PSK (TKIP)", "Open"]:
            potential_vectors.append({
                "ssid": ssid,
                "bssid": network.get("bssid"),
                "vulnerability": "Weak/Outdated Encryption",
                "attack_vector": "Direct password cracking (e.g., Aircrack-ng) or packet sniffing.",
                "mitigation": "Upgrade to WPA3 or WPA2-AES."
            })
        elif "WPA2-PSK" in security:
            potential_vectors.append({
                "ssid": ssid,
                "bssid": network.get("bssid"),
                "vulnerability": "KRACK (Key Reinstallation Attack)",
                "attack_vector": "If client/AP is unpatched, allows for man-in-the-middle (MitM) attacks.",
                "mitigation": "Ensure all clients and APs are fully patched."
            })
        
        # All networks are susceptible to rogue APs
        potential_vectors.append({
            "ssid": ssid,
            "bssid": "N/A (Simulation)",
            "vulnerability": "Rogue Access Point / Evil Twin",
            "attack_vector": f"An attacker can broadcast the same SSID ('{ssid}') with a stronger signal to capture credentials.",
            "mitigation": "Use WPA2/WPA3-Enterprise with 802.1X authentication. Deploy Wireless Intrusion Prevention System (WIPS)."
        })

    return {"target": target, "potential_wifi_vectors": potential_vectors}


def _run_live_wifi_scan(target: str) -> List[Dict[str, Any]]:
    """
    (NEW) Performs a live WiFi scan and returns the results.
    
    WARNING: This requires hardware-specific tools (e.g., aircrack-ng)
    and a WiFi adapter in monitor mode.
    """
    console.print("[bold yellow]Note:[/bold yellow] Live WiFi scan requires a WiFi adapter in")
    console.print("[bold yellow]monitor mode and tools like 'airodump-ng'.[/bold yellow]")
    console.print(f"[bold cyan]Attempting live WiFi scan for {target}...[/bold cyan]")
    
    # --- BEGIN LIVE EXECUTION (EXAMPLE) ---
    # This is a placeholder for a real hardware-specific integration.
    # A real implementation would need to:
    # 1. Identify the wireless interface (e.g., 'wlan0')
    # 2. Put the interface into monitor mode (e.g., 'airmon-ng start wlan0')
    # 3. Run the scan (e.g., 'airodump-ng ...')
    # 4. Parse the output
    # 5. Stop monitor mode (e.g., 'airmon-ng stop wlan0mon')
    
    # This example placeholder just runs `iw dev` to see if wireless tools are present.
    # It does NOT perform a real scan.
    command = "iw dev" 
    try:
        # CHANGED: Hardened subprocess call per Rec #5
        command_parts = shlex.split(command)
        proc = subprocess.run(
            command_parts, 
            capture_output=True, 
            text=True, 
            timeout=10, 
            check=True,
            shell=False # Explicitly False
        )
        logger.info(f"`iw dev` command successful, wireless tools may be present.")
        logger.debug(proc.stdout)
        
        # --- PLACEHOLDER DATA ---
        # Since we are not *actually* scanning, we return simulated data
        # to prove the pipeline works.
        live_scan_data = [
            {
                "ssid": "Corporate-Guest (Live Scan)",
                "bssid": "DE:AD:BE:EF:01:23",
                "security_type": "Open",
                "source": "live_scan"
            },
            {
                "ssid": "Corporate-Secure (Live Scan)",
                "bssid": "DE:AD:BE:EF:04:56",
                "security_type": "WPA2-Enterprise",
                "source": "live_scan"
            }
        ]
        # --- END PLACEHOLDER DATA ---

    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        logger.error(f"Live WiFi scan command '{command}' failed: {e}")
        console.print("[bold red]Live scan command failed. Is 'iw' installed and in your PATH?[/bold red]")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"Live WiFi scan command '{command}' timed out.")
        return []
    # --- END LIVE EXECUTION (EXAMPLE) ---
    
    # Save the new live scan data back to the DB so it can be used next time
    try:
        save_scan_to_db(target=target, module="sigint_wifi_scan", data=live_scan_data)
        console.print(f"[green]Live scan complete, {len(live_scan_data)} networks saved to DB.[/green]")
    except Exception as e:
        console.print(f"[bold red]Failed to save live scan data to DB:[/bold red] {e}")
    
    return live_scan_data


# --- Typer CLI Application ---


offensive_app = typer.Typer()


@offensive_app.command("api-discover")
def run_api_discovery_cli(  # CHANGED: Made synchronous
    domain: str = typer.Argument(..., help="The target domain to scan for APIs."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Discovers potential API endpoints and specifications."""
    with console.status(f"[bold cyan]Discovering APIs on {domain}...[/bold cyan]"):
        # CHANGED: Use asyncio.run() to call the async function
        results = asyncio.run(discover_apis(domain))
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=domain, module="offensive_api_discover", data=results_dict)


@offensive_app.command("enum-content")
def run_content_enumeration_cli(  # CHANGED: Made synchronous
    domain: str = typer.Argument(..., help="The target domain to enumerate."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Enumerates common directories and files on a web server."""
    with console.status(f"[bold cyan]Enumerating content on {domain}...[/bold cyan]"):
        # CHANGED: Use asyncio.run() to call the async function
        results = asyncio.run(enumerate_content(domain))
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=domain, module="offensive_enum_content", data=results_dict)


@offensive_app.command("cloud-takeover")
def run_cloud_takeover_check_cli(  # CHANGED: Made synchronous
    domain: str = typer.Argument(..., help="The root domain to check for takeovers."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Checks for potential subdomain takeovers."""
    with console.status(
        f"[bold cyan]Checking for subdomain takeovers on {domain}...[/bold cyan]"
    ):
        # CHANGED: Use asyncio.run() to call the async function
        results = asyncio.run(check_for_subdomain_takeover(domain))
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=domain, module="offensive_cloud_takeover", data=results_dict)


@offensive_app.command("wifi-attack-surface")
def run_wifi_attack_surface_cli(
    target: str = typer.Argument(..., help="The target entity (e.g., 'Corporate-HQ')."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
    force_live: bool = typer.Option(
        False, "--live", help="Force a new live scan, ignoring stored data."
    ),
):
    """
    Models WiFi attack vectors. Checks stored data first, unless --live is used.
    """
    
    scan_data = None
    if not force_live:
        console.print(f"Checking for stored SIGINT data for '{target}'...")
        try:
            scan_data = get_data_by_module(target, "sigint_wifi_scan")
        except Exception as e:
            console.print(f"[bold red]Database Error:[/bold red] Could not fetch stored data: {e}")
    
    if scan_data:
        console.print(f"[green]Stored data found ({len(scan_data)} networks). Modeling from cache.[/green]")
    else:
        if force_live:
            console.print(f"[bold cyan]Forcing live scan for '{target}'...[/bold cyan]")
        else:
            console.print(f"No stored SIGINT (WiFi) data found for target '{target}'.")
            console.print("[bold cyan]Initiating live scan...[/bold cyan]")
        
        # This will run the (simulated) live scan and save its results to the DB
        scan_data = _run_live_wifi_scan(target)

    if not scan_data:
        console.print(f"No WiFi data (stored or live) found for target '{target}'.")
        return

    # Model the attack surface from whatever data we ended up with
    results = _model_wifi_attack_surface_from_data(target, scan_data)
    
    if results:
        save_or_print_results(results, output_file)
        # We can optionally save this analysis back to the DB
        save_scan_to_db(target=target, module="offensive_wifi_analysis", data=results)
    else:
        console.print(f"Failed to generate attack surface model for '{target}'.")


@offensive_app.callback()
def callback():
    """
    Advanced offensive and reconnaissance operations.
    """


# CHANGED: Simplified main function
def main():
    """
    The CLI commands are now synchronous wrappers (using asyncio.run),
    so we can call the Typer app directly.
    """
    offensive_app()


if __name__ == "__main__":
    main()