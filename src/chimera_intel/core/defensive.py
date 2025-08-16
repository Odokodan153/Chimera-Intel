import typer
import os
import json
import subprocess
import shodan
import time
from rich.panel import Panel
from rich.progress import Progress
from typing import Dict, Any
import logging
from httpx import RequestError, HTTPStatusError
from chimera_intel.core.utils import console, save_or_print_results, is_valid_domain
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.http_client import sync_client
from chimera_intel.core.schemas import HIBPResult, GitHubLeaksResult, TyposquatResult

# Get a logger instance for this specific file

logger = logging.getLogger(__name__)


# --- Data Gathering Functions for Defensive Intelligence ---


def check_hibp_breaches(domain: str, api_key: str) -> HIBPResult:
    """
    Checks a domain against the Have I Been Pwned (HIBP) database for data breaches.

    Args:
        domain (str): The company's domain to check.
        api_key (str): The HIBP API key.

    Returns:
        HIBPResult: A Pydantic model containing a list of breaches, or an error message.
    """
    if not api_key:
        return HIBPResult(error="HIBP API key not found. Check your .env file.")
    url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
    headers = {"hibp-api-key": api_key, "user-agent": "Chimera-Intel-Tool"}
    try:
        response = sync_client.get(url, headers=headers)
        if response.status_code == 404:
            return HIBPResult(breaches=[], message="No breaches found for this domain.")
        response.raise_for_status()
        return HIBPResult(breaches=response.json())
    except HTTPStatusError as e:
        logger.error("HTTP error checking HIBP for '%s': %s", domain, e)
        return HIBPResult(error=f"HTTP error occurred: {e.response.status_code}")
    except RequestError as e:
        logger.error("Network error checking HIBP for '%s': %s", domain, e)
        return HIBPResult(error=f"A network error occurred: {e}")


def search_github_leaks(query: str, api_key: str) -> GitHubLeaksResult:
    """
    Searches GitHub for potential secret leaks related to a query.

    Args:
        query (str): The search term (e.g., 'yourcompany.com "api key"').
        api_key (str): The GitHub Personal Access Token (PAT).

    Returns:
        GitHubLeaksResult: A Pydantic model containing the search results, or an error.
    """
    if not api_key:
        return GitHubLeaksResult(error="GitHub Personal Access Token not found.")
    url = f"https://api.github.com/search/code?q={query}"
    headers = {"Authorization": f"token {api_key}"}
    try:
        response = sync_client.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return GitHubLeaksResult(
            total_count=data.get("total_count"), items=data.get("items", [])
        )
    except HTTPStatusError as e:
        logger.error("HTTP error searching GitHub for query '%s': %s", query, e)
        return GitHubLeaksResult(error=f"HTTP error occurred: {e.response.status_code}")
    except RequestError as e:
        logger.error("Network error searching GitHub for query '%s': %s", query, e)
        return GitHubLeaksResult(error=f"A network error occurred: {e}")


def find_typosquatting_dnstwist(domain: str) -> TyposquatResult:
    """
    Securely uses the dnstwist command-line tool to find potential typosquatting domains.

    Args:
        domain (str): The domain to check for typosquatting variations.

    Returns:
        TyposquatResult: A Pydantic model of the dnstwist JSON output, or an error.
    """
    try:
        command = ["dnstwist", "--json", domain]
        process = subprocess.run(
            command, capture_output=True, text=True, check=True, timeout=120
        )
        return TyposquatResult(results=json.loads(process.stdout))
    except FileNotFoundError:
        logger.error("The 'dnstwist' command was not found. It may not be installed.")
        return TyposquatResult(
            error="dnstwist command not found. Please ensure it is installed."
        )
    except subprocess.CalledProcessError as e:
        logger.error("dnstwist returned an error for domain '%s': %s", domain, e.stderr)
        return TyposquatResult(error=f"dnstwist returned an error: {e.stderr}")
    except Exception as e:
        logger.critical("An unexpected error occurred while running dnstwist: %s", e)
        return TyposquatResult(error=f"An unexpected error occurred: {e}")


def analyze_attack_surface_shodan(query: str, api_key: str) -> Dict[str, Any]:
    """
    Uses Shodan to find devices and services exposed on the internet.

    Args:
        query (str): The Shodan search query (e.g., 'org:"My Company"').
        api_key (str): The Shodan API key.

    Returns:
        Dict[str, Any]: A dictionary of discovered hosts, or an error message.
    """
    if not api_key:
        return {"error": "Shodan API key not found. Check your .env file."}
    try:
        api = shodan.Shodan(api_key)
        results = api.search(query, limit=100)
        hosts = [
            {
                "ip": s.get("ip_str"),
                "port": s.get("port"),
                "org": s.get("org"),
                "hostnames": s.get("hostnames"),
                "data": s.get("data", "").strip(),
            }
            for s in results.get("matches", [])
        ]
        return {"total_results": results.get("total", 0), "hosts": hosts}
    except Exception as e:
        logger.error("An error occurred with Shodan for query '%s': %s", query, e)
        return {"error": f"An error occurred with Shodan: {e}"}


def search_pastes_api(query: str) -> Dict[str, Any]:
    """
    Searches for pastes containing a specific query using the paste.ee API.

    Args:
        query (str): The keyword or domain to search for.

    Returns:
        Dict[str, Any]: A dictionary of found pastes, or an error message.
    """
    url = "https://api.paste.ee/v1/pastes"
    params = {"query": query, "per_page": 20}

    try:
        response = sync_client.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        pastes = [
            {
                "id": p.get("id"),
                "link": p.get("link"),
                "description": p.get("description"),
            }
            for p in data.get("pastes", [])
        ]
        return {"pastes": pastes, "count": len(pastes)}
    except HTTPStatusError as e:
        logger.error("HTTP error searching pastes for query '%s': %s", query, e)
        return {"error": f"HTTP error occurred: {e.response.status_code}"}
    except RequestError as e:
        logger.error("Network error searching pastes for query '%s': %s", query, e)
        return {"error": f"A network error occurred: {e}"}


def analyze_ssl_ssllabs(host: str) -> Dict[str, Any]:
    """
    Performs an in-depth SSL/TLS analysis using the SSL Labs API.

    Args:
        host (str): The hostname to scan (e.g., 'google.com').

    Returns:
        Dict[str, Any]: A dictionary containing the full SSL Labs report, or an error message.
    """
    api_url = "https://api.ssllabs.com/api/v3/"

    def start_scan(hostname):
        """Initiates a new scan."""
        payload = {"host": hostname, "startNew": "on", "all": "done"}
        response = sync_client.get(api_url + "analyze", params=payload)
        response.raise_for_status()
        return response.json()

    def poll_scan(hostname):
        """Polls for the scan results."""
        payload = {"host": hostname, "all": "done"}
        while True:
            time.sleep(15)
            response = sync_client.get(api_url + "analyze", params=payload)
            response.raise_for_status()
            data = response.json()
            if data["status"] in ("READY", "ERROR"):
                return data

    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Starting SSL Labs scan...", total=None)
            initial_data = start_scan(host)

            if initial_data["status"] == "ERROR":
                return {
                    "error": initial_data.get(
                        "statusMessage", "Unknown error starting scan."
                    )
                }
            progress.update(
                task,
                description="[cyan]Scan in progress... (this can take a few minutes)",
            )
            final_data = poll_scan(host)
            progress.update(task, completed=100, description="[green]Scan complete!")
        return final_data
    except (HTTPStatusError, RequestError) as e:
        logger.error("An error occurred with SSL Labs API for host '%s': %s", host, e)
        return {"error": f"An error occurred with SSL Labs API: {e}"}


def analyze_apk_mobsf(file_path: str, mobsf_url: str, api_key: str) -> Dict[str, Any]:
    """
    Uploads an Android APK to a running MobSF instance and retrieves the scan results.

    Args:
        file_path (str): The local path to the .apk file.
        mobsf_url (str): The URL of the running MobSF instance.
        api_key (str): The MobSF REST API key.

    Returns:
        Dict[str, Any]: The full JSON report from MobSF, or an error message.
    """
    if not os.path.exists(file_path):
        logger.error("APK file not found at path: %s", file_path)
        return {"error": f"File not found at path: {file_path}"}
    if not mobsf_url or not api_key:
        return {"error": "MobSF URL and API Key are required."}
    headers = {"Authorization": api_key}

    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            upload_response = sync_client.post(
                f"{mobsf_url}/api/v1/upload", headers=headers, files=files
            )
            upload_response.raise_for_status()
        upload_data = upload_response.json()

        scan_response = sync_client.post(
            f"{mobsf_url}/api/v1/scan", headers=headers, data=upload_data
        )
        scan_response.raise_for_status()

        report_response = sync_client.post(
            f"{mobsf_url}/api/v1/report_json", headers=headers, data=upload_data
        )
        report_response.raise_for_status()

        return report_response.json()
    except (HTTPStatusError, RequestError) as e:
        logger.error("An error occurred with MobSF API: %s", e)
        return {"error": f"An error occurred with MobSF API: {e}"}


# --- Typer CLI Application ---

defensive_app = typer.Typer()


@defensive_app.command("breaches")
def run_breach_check(domain: str, output_file: str = None):
    """Checks your domain against the Have I Been Pwned database."""
    if not is_valid_domain(domain):
        logger.warning(
            "Invalid domain format provided to 'breaches' command: %s", domain
        )
        console.print(
            Panel(
                f"[bold red]Invalid Input:[/] '{domain}' is not a valid domain format.",
                title="Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    logger.info("Starting HIBP breach check for %s", domain)
    api_key = API_KEYS.hibp_api_key
    results = check_hibp_breaches(domain, api_key)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(
        target=domain, module="defensive_breaches", data=results.model_dump()
    )


@defensive_app.command("leaks")
def run_leaks_check(query: str, output_file: str = None):
    """Searches GitHub for potential code and secret leaks."""
    logger.info("Starting GitHub leaks search for query: '%s'", query)
    api_key = API_KEYS.github_pat
    results = search_github_leaks(query, api_key)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(target=query, module="defensive_leaks", data=results.model_dump())


@defensive_app.command("typosquat")
def run_typosquat_check(domain: str, output_file: str = None):
    """Finds potential phishing domains similar to yours using dnstwist."""
    if not is_valid_domain(domain):
        logger.warning(
            "Invalid domain format provided to 'typosquat' command: %s", domain
        )
        console.print(
            Panel(
                f"[bold red]Invalid Input:[/] '{domain}' is not a valid domain format.",
                title="Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    logger.info("Starting typosquatting check for %s", domain)
    results = find_typosquatting_dnstwist(domain)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(
        target=domain, module="defensive_typosquat", data=results.model_dump()
    )


@defensive_app.command("surface")
def run_surface_check(query: str, output_file: str = None):
    """Analyzes your public attack surface using Shodan."""
    logger.info("Starting Shodan surface scan for query: '%s'", query)
    api_key = API_KEYS.shodan_api_key
    results = analyze_attack_surface_shodan(query, api_key)
    save_or_print_results(results, output_file)
    save_scan_to_db(target=query, module="defensive_surface", data=results)


@defensive_app.command("pastebin")
def run_pastebin_check(query: str, output_file: str = None):
    """Searches public pastes for a query using the paste.ee API."""
    logger.info("Starting public paste search for query: '%s'", query)
    results = search_pastes_api(query)
    save_or_print_results(results, output_file)
    save_scan_to_db(target=query, module="defensive_pastebin", data=results)


@defensive_app.command("ssllabs")
def run_ssllabs_check(domain: str, output_file: str = None):
    """Performs an in-depth SSL/TLS analysis via SSL Labs."""
    if not is_valid_domain(domain):
        logger.warning(
            "Invalid domain format provided to 'ssllabs' command: %s", domain
        )
        console.print(
            Panel(
                f"[bold red]Invalid Input:[/] '{domain}' is not a valid domain format.",
                title="Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    logger.info("Starting SSL Labs scan for %s", domain)
    results = analyze_ssl_ssllabs(domain)
    save_or_print_results(results, output_file)
    save_scan_to_db(target=domain, module="defensive_ssllabs", data=results)


@defensive_app.command("mobsf")
def run_mobsf_scan(
    apk_file: str = typer.Option(
        ..., "--apk-file", help="Path to the .apk file to be analyzed."
    ),
    mobsf_url: str = typer.Option(
        "http://122.0.0.1:8000", help="URL of your running MobSF instance."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Analyzes an Android .apk file using a local MobSF instance."""
    logger.info("Starting MobSF scan for APK file: %s", apk_file)
    api_key = API_KEYS.mobsf_api_key
    if not api_key:
        logger.error("MOBSF_API_KEY not found in .env file.")
        raise typer.Exit(code=1)
    results = analyze_apk_mobsf(apk_file, mobsf_url, api_key)
    save_or_print_results(results, output_file)
    save_scan_to_db(
        target=os.path.basename(apk_file), module="defensive_mobsf", data=results
    )
