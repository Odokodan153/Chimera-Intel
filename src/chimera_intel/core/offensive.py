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
from typing import Optional, List, Set
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
from .database import save_scan_to_db

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