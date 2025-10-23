"""
Defensive counter-intelligence and security scanning module.

This module contains functions for an organization to assess its own digital
footprint from an attacker's perspective. It includes checks for data breaches
(Have I Been Pwned), code leaks (GitHub), typosquatting domains (dnstwist),
exposed assets (Shodan), and more.
"""

import json
import logging
import os
import subprocess
import time
from typing import Any, Dict, Optional, Union

import shodan  # type: ignore
import typer
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.http_client import sync_client
from chimera_intel.core.schemas import (
    Certificate,
    CTMentorResult,
    FoundSecret,
    GitHubLeaksResult,
    HIBPResult,
    IaCScanResult,
    IaCSecurityIssue,
    MobSFResult,
    MozillaObservatoryResult,
    Paste,
    PasteResult,
    SecretsScanResult,
    ShodanHost,
    ShodanResult,
    SSLLabsResult,
    TyposquatResult,
)
from chimera_intel.core.utils import console, is_valid_domain, save_or_print_results
from httpx import HTTPStatusError, RequestError
from rich.panel import Panel
from rich.progress import Progress

# Get a logger instance for this specific file


logger = logging.getLogger(__name__)


# --- Data Gathering Functions for Defensive Intelligence ---


def check_hibp_breaches(domain: str, api_key: str) -> HIBPResult:
    """Checks a domain against the Have I Been Pwned (HIBP) database for data breaches.
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
    except Exception as e:
        logger.error(
            "An unexpected error occurred checking HIBP for '%s': %s", domain, e
        )
        return HIBPResult(error=f"An unexpected error occurred: {e}")


def search_github_leaks(query: str, api_key: str) -> GitHubLeaksResult:
    """Searches GitHub for potential secret leaks related to a query.
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
    """Securely uses the dnstwist command-line tool to find potential typosquatting domains.
    Args:
        domain (str): The domain to check for typosquatting variations.

    Returns:
        TyposquatResult: A Pydantic model of the dnstwist JSON output, or an error.
    """
    if domain.startswith("-"):
        logger.error("Invalid domain format for dnstwist scan: '%s'", domain)
        return TyposquatResult(
            error="Invalid domain format. Cannot start with a hyphen."
        )
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


def analyze_attack_surface_shodan(query: str, api_key: str) -> ShodanResult:
    """Uses Shodan to find devices and services exposed on the internet.
    Args:
        query (str): The Shodan search query (e.g., 'org:"My Company"').
        api_key (str): The Shodan API key.

    Returns:
        ShodanResult: A Pydantic model of discovered hosts, or an error message.
    """
    if not api_key:
        return ShodanResult(error="Shodan API key not found. Check your .env file.")
    try:
        api = shodan.Shodan(api_key)
        results = api.search(query, limit=100)
        hosts = [
            ShodanHost(
                ip=s.get("ip_str"),
                port=s.get("port"),
                org=s.get("org"),
                hostnames=s.get("hostnames"),
                data=s.get("data", "").strip(),
            )
            for s in results.get("matches", [])
        ]
        return ShodanResult(total_results=results.get("total", 0), hosts=hosts)
    except Exception as e:
        logger.error("An error occurred with Shodan for query '%s': %s", query, e)
        return ShodanResult(error=f"An error occurred with Shodan: {e}")


def search_pastes_api(query: str) -> PasteResult:
    """Searches for pastes containing a specific query using the paste.ee API.
    Args:
        query (str): The keyword or domain to search for.

    Returns:
        PasteResult: A Pydantic model of found pastes, or an error message.
    """
    url = "https://api.paste.ee/v1/pastes"
    params: Dict[str, Union[str, int]] = {"query": query, "per_page": 20}
    try:
        response = sync_client.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        pastes = [
            Paste(
                id=p.get("id"),
                link=p.get("link"),
                description=p.get("description"),
            )
            for p in data.get("pastes", [])
        ]
        return PasteResult(pastes=pastes, count=len(pastes))
    except HTTPStatusError as e:
        logger.error("HTTP error searching pastes for query '%s': %s", query, e)
        return PasteResult(error=f"HTTP error occurred: {e.response.status_code}")
    except RequestError as e:
        logger.error("Network error searching pastes for query '%s': %s", query, e)
        return PasteResult(error=f"A network error occurred: {e}")


def analyze_ssl_ssllabs(host: str) -> SSLLabsResult:
    """Performs an in-depth SSL/TLS analysis using the SSL Labs API.
    Args:
        host (str): The hostname to scan (e.g., 'google.com').

    Returns:
        SSLLabsResult: A Pydantic model containing the full SSL Labs report, or an error message.
    """
    api_url = "https://api.ssllabs.com/api/v3/"

    def start_scan(hostname: str) -> Dict[str, Any]:
        """Initiates a new scan."""
        payload: Dict[str, Any] = {"host": hostname, "startNew": "on", "all": "done"}
        response = sync_client.get(api_url + "analyze", params=payload)
        response.raise_for_status()
        return response.json()

    def poll_scan(hostname: str) -> Dict[str, Any]:
        """Polls for the scan results."""
        payload: Dict[str, Any] = {"host": hostname, "all": "done"}
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
                return SSLLabsResult(
                    error=initial_data.get(
                        "statusMessage", "Unknown error starting scan."
                    )
                )
            progress.update(
                task,
                description="[cyan]Scan in progress... (this can take a few minutes)",
            )
            final_data = poll_scan(host)
            progress.update(task, completed=100, description="[green]Scan complete!")
        return SSLLabsResult(report=final_data)
    except (HTTPStatusError, RequestError) as e:
        logger.error("An error occurred with SSL Labs API for host '%s': %s", host, e)
        return SSLLabsResult(error=f"An error occurred with SSL Labs API: {e}")


def analyze_apk_mobsf(file_path: str, mobsf_url: str, api_key: str) -> MobSFResult:
    """Uploads an Android APK to a running MobSF instance and retrieves the scan results.
    Args:
        file_path (str): The local path to the .apk file.
        mobsf_url (str): The URL of the running MobSF instance.
        api_key (str): The MobSF REST API key.

    Returns:
        MobSFResult: The full JSON report from MobSF, or an error message.
    """
    if not os.path.exists(file_path):
        logger.error("APK file not found at path: %s", file_path)
        return MobSFResult(error=f"File not found at path: {file_path}")
    if not mobsf_url or not api_key:
        return MobSFResult(error="MobSF URL and API Key are required.")
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
        return MobSFResult(report=report_response.json())
    except (HTTPStatusError, RequestError) as e:
        logger.error("An error occurred with MobSF API: %s", e)
        return MobSFResult(error=f"An error occurred with MobSF API: {e}")


# --- : Certificate Transparency Monitoring ---


def monitor_ct_logs(domain: str) -> CTMentorResult:
    """Monitors Certificate Transparency logs for new SSL/TLS certificates via crt.sh.

    This function queries the public crt.sh service, which aggregates certificate
    transparency logs from multiple sources. It searches for any certificates
    that have been issued for the specified domain and its subdomains.

    Args:
        domain (str): The domain to query for newly issued certificates (e.g., "example.com").

    Returns:
        CTMentorResult: A Pydantic model containing the list of found certificates
                        or an error message if the request fails.
    """
    logger.info(f"Monitoring CT logs for new certificates for {domain}")
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        response = sync_client.get(url, timeout=30)
        response.raise_for_status()
        certs_data = response.json()

        certs = [
            Certificate(
                issuer_name=cert.get("issuer_name", "N/A"),
                not_before=cert.get("not_before", "N/A"),
                not_after=cert.get("not_after", "N/A"),
                subject_name=cert.get("name_value", "N/A"),
            )
            for cert in certs_data
        ]
        return CTMentorResult(domain=domain, total_found=len(certs), certificates=certs)
    except Exception as e:
        logger.error(f"Failed to fetch CT logs for {domain}: {e}")
        return CTMentorResult(
            domain=domain,
            total_found=0,
            error=f"An error occurred while fetching CT logs: {e}",
        )


# --- : IaC Scanning ---


def scan_iac_files(directory: str) -> IaCScanResult:
    """Scans Infrastructure as Code (IaC) files for security issues using tfsec.

    This function executes the 'tfsec' command-line tool, which must be installed
    on the system and available in the system's PATH. It scans the specified directory
    for common misconfigurations in infrastructure files (like Terraform) and
    parses the JSON output.

    Args:
        directory (str): The local file path to the directory containing IaC files.

    Returns:
        IaCScanResult: A Pydantic model containing a list of security issues found,
                       or an error if tfsec is not found or fails to execute.
    """
    logger.info(f"Scanning IaC files in directory: {directory}")

    if not os.path.isdir(directory):
        return IaCScanResult(
            target_path=directory,
            total_issues=0,
            error="Provided path is not a valid directory.",
        )
    try:
        command = ["tfsec", directory, "--format", "json"]
        process = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=300
        )

        # tfsec exits with code 1 if issues are found, so we don't use check=True

        if process.returncode != 0 and process.stderr:
            # Check for "tfsec command not found" or similar

            if (
                "command not found" in process.stderr.lower()
                or "no such file" in process.stderr.lower()
            ):
                raise FileNotFoundError("tfsec command not found.")
        data = json.loads(process.stdout)

        issues = [
            IaCSecurityIssue(
                file_path=result.get("location", {}).get("filename", "N/A"),
                line_number=result.get("location", {}).get("start_line", 0),
                issue_id=result.get("rule_id", "N/A"),
                description=result.get("description", "N/A"),
                severity=result.get("severity", "UNKNOWN"),
            )
            for result in data.get("results", [])
        ]

        return IaCScanResult(
            target_path=directory, total_issues=len(issues), issues=issues
        )
    except FileNotFoundError:
        logger.error(
            "The 'tfsec' command was not found. Please ensure it is installed and in your PATH."
        )
        return IaCScanResult(
            target_path=directory,
            total_issues=0,
            error="tfsec command not found. Please ensure it is installed.",
        )
    except json.JSONDecodeError:
        logger.error(f"Failed to parse tfsec JSON output. Error: {process.stderr}")
        return IaCScanResult(
            target_path=directory,
            total_issues=0,
            error="Failed to parse tfsec JSON output.",
        )
    except Exception as e:
        logger.critical(f"An unexpected error occurred while running tfsec: {e}")
        return IaCScanResult(
            target_path=directory,
            total_issues=0,
            error=f"An unexpected error occurred: {e}",
        )


# --- : Secrets Scanning ---


def scan_for_secrets(directory: str) -> SecretsScanResult:
    """Scans a directory for hardcoded secrets using gitleaks.

    This function executes the 'gitleaks' command-line tool, which must be
    installed on the system and available in the system's PATH. It scans the specified
    directory for secrets like API keys, passwords, and other sensitive credentials
    and parses the JSON report that gitleaks generates.

    Args:
        directory (str): The local file path to the directory to scan.

    Returns:
        SecretsScanResult: A Pydantic model containing a list of found secrets,
                           or an error if gitleaks is not found or fails to execute.
    """

    logger.info(f"Scanning for hardcoded secrets in directory: {directory}")

    if not os.path.isdir(directory):
        return SecretsScanResult(
            target_path=directory,
            total_found=0,
            error="Provided path is not a valid directory.",
        )
    try:
        report_path = "gitleaks-report.json"
        command = [
            "gitleaks",
            "detect",
            "--source",
            directory,
            "--report-path",
            report_path,
            "--report-format",
            "json",
            "--no-git",  # Scan the directory as-is, not as a git repo
        ]
        # Use check=False as gitleaks exits with a non-zero code if secrets are found

        subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=300
        )

        if not os.path.exists(report_path):
            return SecretsScanResult(target_path=directory, total_found=0, secrets=[])
        with open(report_path, "r") as f:
            data = json.load(f)
        secrets = [
            FoundSecret(
                file_path=finding.get("File", "N/A"),
                line_number=finding.get("StartLine", 0),
                rule_id=finding.get("RuleID", "N/A"),
                secret_type=finding.get("Description", "N/A"),
            )
            for finding in data
        ]

        # Clean up the report file

        os.remove(report_path)

        return SecretsScanResult(
            target_path=directory, total_found=len(secrets), secrets=secrets
        )
    except FileNotFoundError:
        logger.error(
            "The 'gitleaks' command was not found. Please ensure it is installed and in your PATH."
        )
        return SecretsScanResult(
            target_path=directory,
            total_found=0,
            error="gitleaks command not found. Please ensure it is installed.",
        )
    except Exception as e:
        logger.critical(f"An unexpected error occurred while running gitleaks: {e}")
        return SecretsScanResult(
            target_path=directory,
            total_found=0,
            error=f"An unexpected error occurred: {e}",
        )


def analyze_mozilla_observatory(domain: str) -> Optional[MozillaObservatoryResult]:
    """
    Analyzes a domain's security headers using the public Mozilla Observatory API.

    Args:
        domain (str): The domain to analyze.

    Returns:
        Optional[MozillaObservatoryResult]: A Pydantic model with the scan summary, or None on error.
    """
    base_url = "https://http-observatory.security.mozilla.org/api/v1"
    analyze_url = f"{base_url}/analyze"
    logger.info(f"Initiating Mozilla Observatory scan for {domain}")

    try:
        # Step 1: Initiate the scan

        initial_response = sync_client.post(
            analyze_url, data={"host": domain, "hidden": "true"}
        )
        initial_response.raise_for_status()
        scan_data = initial_response.json()

        scan_id = scan_data.get("scan_id")
        if not scan_id:
            logger.error(f"Could not get scan_id from Observatory for {domain}")
            return None
        # Step 2: Poll for results

        start_time = time.time()
        while time.time() - start_time < 180:  # 3-minute timeout
            time.sleep(5)
            scan_response = sync_client.get(analyze_url, params={"scan": scan_id})
            scan_response.raise_for_status()
            scan_data = scan_response.json()

            state = scan_data.get("state")
            if state == "FINISHED":
                logger.info(f"Observatory scan for {domain} finished.")
                return MozillaObservatoryResult(
                    scan_id=scan_data.get("scan_id"),
                    score=scan_data.get("score"),
                    grade=scan_data.get("grade"),
                    state=scan_data.get("state"),
                    tests_passed=scan_data.get("tests_passed"),
                    tests_failed=scan_data.get("tests_failed"),
                    report_url=f"https://observatory.mozilla.org/analyze/{domain}",
                )
            elif state == "FAILED":
                logger.error(f"Observatory scan for {domain} failed.")
                return MozillaObservatoryResult(
                    scan_id=scan_id,
                    score=0,
                    grade="F",
                    state="FAILED",
                    tests_passed=0,
                    tests_failed=12,
                    report_url=f"https://observatory.mozilla.org/analyze/{domain}",
                    error="Scan failed on the server side.",
                )
            logger.debug(f"Observatory scan for {domain} is in state: {state}")
        logger.warning(f"Observatory scan for {domain} timed out after 3 minutes.")
        return None
    except Exception as e:
        logger.error(
            f"An API error occurred with Mozilla Observatory for {domain}: {e}"
        )
        return None


# --- Typer CLI Application ---


defensive_app = typer.Typer()


@defensive_app.command("breaches")
def run_breach_check(
    domain: str = typer.Argument(..., help="The domain to check against HIBP."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
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
    api_key = API_KEYS.hibp_api_key
    if not api_key:
        console.print(
            Panel(
                "[bold yellow]Skipping HIBP Scan:[/bold yellow] `HIBP_API_KEY` not found in your .env file.",
                title="[yellow]Configuration Warning[/yellow]",
                border_style="yellow",
            )
        )
        # --- FIX: Changed 'return' to 'raise typer.Exit(code=1)' ---
        raise typer.Exit(code=1)
        
    logger.info("Starting HIBP breach check for %s", domain)
    results = check_hibp_breaches(domain, api_key)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(
        target=domain, module="defensive_breaches", data=results.model_dump()
    )


@defensive_app.command("leaks")
def run_leaks_check(
    query: str = typer.Argument(
        ..., help="The search query for GitHub (e.g., 'mycompany.com api_key')."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Searches GitHub for potential code and secret leaks."""
    api_key = API_KEYS.github_pat
    if not api_key:
        console.print(
            Panel(
                "[bold yellow]Skipping GitHub Leaks Scan:[/bold yellow] `GITHUB_PAT` not found in your .env file.",
                title="[yellow]Configuration Warning[/yellow]",
                border_style="yellow",
            )
        )
        return
    logger.info("Starting GitHub leaks search for query: '%s'", query)
    results = search_github_leaks(query, api_key)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(target=query, module="defensive_leaks", data=results.model_dump())


@defensive_app.command("typosquat")
def run_typosquat_check(
    domain: str = typer.Argument(
        ..., help="The domain to check for similar-looking domains."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
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
def run_surface_check(
    query: str = typer.Argument(
        ..., help="The Shodan search query (e.g., 'org:\"My Company\"')."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Analyzes your public attack surface using Shodan."""
    api_key = API_KEYS.shodan_api_key
    if not api_key:
        console.print(
            Panel(
                "[bold yellow]Skipping Shodan Scan:[/bold yellow] `SHODAN_API_KEY` not found in your .env file.",
                title="[yellow]Configuration Warning[/yellow]",
                border_style="yellow",
            )
        )
        return
    logger.info("Starting Shodan surface scan for query: '%s'", query)
    results = analyze_attack_surface_shodan(query, api_key)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(target=query, module="defensive_surface", data=results.model_dump())


@defensive_app.command("pastebin")
def run_pastebin_check(
    query: str = typer.Argument(
        ..., help="The keyword or domain to search for in public pastes."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Searches public pastes for a query using the paste.ee API."""
    logger.info("Starting public paste search for query: '%s'", query)
    results = search_pastes_api(query)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(
        target=query, module="defensive_pastebin", data=results.model_dump()
    )


@defensive_app.command("ssllabs")
def run_ssllabs_check(
    domain: str = typer.Argument(
        ..., help="The domain to perform an SSL/TLS analysis on."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
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
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(
        target=domain, module="defensive_ssllabs", data=results.model_dump()
    )


@defensive_app.command("mobsf")
def run_mobsf_scan(
    apk_file: str = typer.Option(
        ..., "--apk-file", help="Path to the .apk file to be analyzed."
    ),
    mobsf_url: str = typer.Option(
        "http://127.0.0.1:8000", help="URL of your running MobSF instance."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Analyzes an Android .apk file using a local MobSF instance."""
    api_key = API_KEYS.mobsf_api_key
    if not api_key:
        console.print(
            Panel(
                "[bold yellow]Skipping MobSF Scan:[/bold yellow] `MOBSF_API_KEY` not found in your .env file.",
                title="[yellow]Configuration Warning[/yellow]",
                border_style="yellow",
            )
        )
        raise typer.Exit(code=1)
    logger.info("Starting MobSF scan for APK file: %s", apk_file)
    results = analyze_apk_mobsf(apk_file, mobsf_url, api_key)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(
        target=os.path.basename(apk_file),
        module="defensive_mobsf",
        data=results.model_dump(),
    )


@defensive_app.command("certs")
def run_ct_log_check(
    domain: str = typer.Argument(..., help="The domain to check for new certificates."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Monitors Certificate Transparency logs for newly issued SSL certificates."""
    results = monitor_ct_logs(domain)
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=domain, module="defensive_certs", data=results_dict)


@defensive_app.command("scan-iac")
def run_iac_scan(
    directory: str = typer.Argument(..., help="Path to the directory with IaC files."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Scans Infrastructure as Code (Terraform, etc.) for security issues."""
    results = scan_iac_files(directory)
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=os.path.basename(directory),
        module="defensive_scan_iac",
        data=results_dict,
    )


@defensive_app.command("scan-secrets")
def run_secrets_scan(
    directory: str = typer.Argument(
        ..., help="Path to the source code directory to scan."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Scans a local directory for hardcoded secrets."""
    results = scan_for_secrets(directory)
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=os.path.basename(directory),
        module="defensive_scan_secrets",
        data=results_dict,
    )