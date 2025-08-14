import typer
import os
import json
import subprocess
import shodan
import time
from rich.panel import Panel
from rich.progress import Progress
from typing import Dict, Any

# --- CORRECTED Absolute Imports ---
from chimera_intel.core.utils import console, save_or_print_results, is_valid_domain
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.http_client import sync_client

# --- Data Gathering Functions for Defensive Intelligence ---

def check_hibp_breaches(domain: str, api_key: str) -> Dict[str, Any]:
    """
    Checks a domain against the Have I Been Pwned (HIBP) database for data breaches.

    Args:
        domain (str): The company's domain to check.
        api_key (str): The HIBP API key.

    Returns:
        Dict[str, Any]: A dictionary containing a list of breaches, or an error message.
    """
    if not api_key:
        return {"error": "HIBP API key not found. Check your .env file."}
    url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
    headers = {"hibp-api-key": api_key, "user-agent": "Chimera-Intel-Tool"}
    try:
        response = sync_client.get(url, headers=headers)
        if response.status_code == 404:
            return {"breaches": [], "message": "No breaches found for this domain."}
        response.raise_for_status()
        return {"breaches": response.json()}
    except Exception as e:
        return {"error": f"An error occurred with HIBP API: {e}"}

def search_github_leaks(query: str, api_key: str) -> Dict[str, Any]:
    """
    Searches GitHub for potential secret leaks related to a query.

    Args:
        query (str): The search term (e.g., 'yourcompany.com "api key"').
        api_key (str): The GitHub Personal Access Token (PAT).

    Returns:
        Dict[str, Any]: A dictionary containing the search results, or an error message.
    """
    if not api_key:
        return {"error": "GitHub Personal Access Token not found. Check your .env file."}
    url = f"https://api.github.com/search/code?q={query}"
    headers = {"Authorization": f"token {api_key}"}
    try:
        response = sync_client.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        items = [{"url": item.get("html_url"), "repository": item.get("repository", {}).get("full_name")} for item in data.get("items", [])]
        return {"total_count": data.get("total_count"), "items": items}
    except Exception as e:
        return {"error": f"An error occurred with GitHub search: {e}"}

def find_typosquatting_dnstwist(domain: str) -> Dict[str, Any]:
    """
    Securely uses the dnstwist command-line tool to find potential typosquatting domains.

    Args:
        domain (str): The domain to check for typosquatting variations.

    Returns:
        Dict[str, Any]: A dictionary of the dnstwist JSON output, or an error message.
    """
    try:
        command = ["dnstwist", "--json", domain]
        process = subprocess.run(
            command,
            capture_output=True, text=True, check=True, timeout=120
        )
        return json.loads(process.stdout)
    except FileNotFoundError:
        return {"error": "dnstwist command not found. Please ensure it is installed and in your system's PATH."}
    except subprocess.CalledProcessError as e:
        return {"error": f"dnstwist returned an error: {e.stderr}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred while running dnstwist: {e}"}

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
        hosts = [{"ip": s.get('ip_str'), "port": s.get('port'), "org": s.get('org'), "hostnames": s.get('hostnames'), "data": s.get('data', '').strip()} for s in results.get('matches', [])]
        return {"total_results": results.get('total', 0), "hosts": hosts}
    except Exception as e:
        return {"error": f"An error occurred with Shodan: {e}"}

def search_pastebin_psbdmp(query: str) -> Dict[str, Any]:
    """
    Securely searches Pastebin dumps for a specific query using the psbdmp tool.

    Args:
        query (str): The keyword or domain to search for.

    Returns:
        Dict[str, Any]: A dictionary of found pastes, or an error message.
    """
    try:
        command = ["psbdmp", "-q", query, "-j"]
        process = subprocess.run(
            command,
            capture_output=True, text=True, check=True, timeout=60
        )
        pastes = [json.loads(line) for line in process.stdout.strip().split('\n') if line]
        return {"pastes": pastes, "count": len(pastes)}
    except FileNotFoundError:
        return {"error": "psbdmp command not found. Please ensure it is installed (`pip install psbdmp`)."}
    except subprocess.CalledProcessError:
        return {"pastes": [], "message": "No results found."}
    except Exception as e:
        return {"error": f"An unexpected error occurred while running psbdmp: {e}"}

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
        payload = {'host': hostname, 'startNew': 'on', 'all': 'done'}
        response = sync_client.get(api_url + "analyze", params=payload)
        response.raise_for_status()
        return response.json()

    def poll_scan(hostname):
        """Polls for the scan results."""
        payload = {'host': hostname, 'all': 'done'}
        while True:
            response = sync_client.get(api_url + "analyze", params=payload)
            response.raise_for_status()
            data = response.json()
            if data['status'] in ('READY', 'ERROR'):
                return data
            time.sleep(15)
    
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Starting SSL Labs scan...", total=None)
            initial_data = start_scan(host)
            
            if initial_data['status'] == 'ERROR':
                return {"error": initial_data.get("statusMessage", "Unknown error starting scan.")}

            progress.update(task, description="[cyan]Scan in progress... (this can take a few minutes)")
            final_data = poll_scan(host)
            progress.update(task, completed=100, description="[green]Scan complete!")

        return final_data
    except Exception as e:
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
        return {"error": f"File not found at path: {file_path}"}
    if not mobsf_url or not api_key:
        return {"error": "MobSF URL and API Key are required."}
        
    headers = {'Authorization': api_key}
    
    try:
        console.print(" [cyan]>[/cyan] Uploading APK to MobSF...")
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            upload_response = sync_client.post(f"{mobsf_url}/api/v1/upload", headers=headers, files=files)
            upload_response.raise_for_status()
        upload_data = upload_response.json()
        
        console.print(" [cyan]>[/cyan] Starting MobSF scan...")
        scan_response = sync_client.post(f"{mobsf_url}/api/v1/scan", headers=headers, data=upload_data)
        scan_response.raise_for_status()
        
        console.print(" [cyan]>[/cyan] Fetching MobSF JSON report...")
        report_response = sync_client.post(f"{mobsf_url}/api/v1/report_json", headers=headers, data=upload_data)
        report_response.raise_for_status()
        
        return report_response.json()
    except Exception as e:
        return {"error": f"An error occurred with MobSF API: {e}"}


# --- Typer CLI Application ---
defensive_app = typer.Typer()

@defensive_app.command("breaches")
def run_breach_check(
    domain: str = typer.Argument(..., help="Your company's domain to check for breaches."),
    output_file: str = typer.Option(None, "--output", "-o", help="Save results to a JSON file.")
):
    """Checks your domain against the Have I Been Pwned database."""
    if not is_valid_domain(domain):
        console.print(Panel(f"[bold red]Invalid Input:[/] '{domain}' is not a valid domain format.", title="Error", border_style="red"))
        raise typer.Exit(code=1)

    console.print(Panel(f"[bold red]Checking for Breaches at {domain}[/bold red]", title="Chimera Intel | Defensive", border_style="red"))
    api_key = API_KEYS.hibp_api_key
    results = check_hibp_breaches(domain, api_key)
    save_or_print_results(results, output_file)
    save_scan_to_db(target=domain, module="defensive_breaches", data=results)

@defensive_app.command("leaks")
def run_leaks_check(
    query: str = typer.Argument(..., help="Search query, e.g., 'yourcompany.com password'"),
    output_file: str = typer.Option(None, "--output", "-o", help="Save results to a JSON file.")
):
    """Searches GitHub for potential code and secret leaks."""
    console.print(Panel(f"[bold red]Searching GitHub for leaks: '{query}'[/bold red]", title="Chimera Intel | Defensive", border_style="red"))
    api_key = API_KEYS.github_pat
    results = search_github_leaks(query, api_key)
    save_or_print_results(results, output_file)
    save_scan_to_db(target=query, module="defensive_leaks", data=results)

@defensive_app.command("typosquat")
def run_typosquat_check(
    domain: str = typer.Argument(..., help="Your company's domain to check for typosquatting."),
    output_file: str = typer.Option(None, "--output", "-o", help="Save results to a JSON file.")
):
    """Finds potential phishing domains similar to yours using dnstwist."""
    if not is_valid_domain(domain):
        console.print(Panel(f"[bold red]Invalid Input:[/] '{domain}' is not a valid domain format.", title="Error", border_style="red"))
        raise typer.Exit(code=1)

    console.print(Panel(f"[bold red]Checking for Typosquatting Domains for {domain}[/bold red]", title="Chimera Intel | Defensive", border_style="red"))
    results = find_typosquatting_dnstwist(domain)
    save_or_print_results(results, output_file)
    save_scan_to_db(target=domain, module="defensive_typosquat", data=results)

@defensive_app.command("surface")
def run_surface_check(
    query: str = typer.Argument(..., help="Shodan search query, e.g., 'org:\"My Company\"'"),
    output_file: str = typer.Option(None, "--output", "-o", help="Save results to a JSON file.")
):
    """Analyzes your public attack surface using Shodan."""
    console.print(Panel(f"[bold red]Analyzing Attack Surface with Shodan: '{query}'[/bold red]", title="Chimera Intel | Defensive", border_style="red"))
    api_key = API_KEYS.shodan_api_key
    results = analyze_attack_surface_shodan(query, api_key)
    save_or_print_results(results, output_file)
    save_scan_to_db(target=query, module="defensive_surface", data=results)

@defensive_app.command("pastebin")
def run_pastebin_check(
    query: str = typer.Argument(..., help="Keyword or domain to search for in Pastebin dumps."),
    output_file: str = typer.Option(None, "--output", "-o", help="Save results to a JSON file.")
):
    """Searches Pastebin dumps using psbdmp."""
    console.print(Panel(f"[bold red]Searching Pastebin for: '{query}'[/bold red]", title="Chimera Intel | Defensive", border_style="red"))
    results = search_pastebin_psbdmp(query)
    save_or_print_results(results, output_file)
    save_scan_to_db(target=query, module="defensive_pastebin", data=results)

@defensive_app.command("ssllabs")
def run_ssllabs_check(
    domain: str = typer.Argument(..., help="The domain to run an SSL Labs analysis on."),
    output_file: str = typer.Option(None, "--output", "-o", help="Save results to a JSON file.")
):
    """Performs an in-depth SSL/TLS analysis via SSL Labs."""
    if not is_valid_domain(domain):
        console.print(Panel(f"[bold red]Invalid Input:[/] '{domain}' is not a valid domain format.", title="Error", border_style="red"))
        raise typer.Exit(code=1)

    console.print(Panel(f"[bold red]Starting full SSL/TLS analysis for {domain}[/bold red]", title="Chimera Intel | Defensive", border_style="red"))
    results = analyze_ssl_ssllabs(domain)
    save_or_print_results(results, output_file)
    save_scan_to_db(target=domain, module="defensive_ssllabs", data=results)

@defensive_app.command("mobsf")
def run_mobsf_scan(
    apk_file: str = typer.Option(..., "--apk-file", help="Path to the .apk file to be analyzed."),
    mobsf_url: str = typer.Option("http://127.0.0.1:8000", help="URL of your running MobSF instance."),
    output_file: str = typer.Option(None, "--output", "-o", help="Save results to a JSON file.")
):
    """Analyzes an Android .apk file using a local MobSF instance."""
    console.print(Panel(f"[bold red]Analyzing mobile app: {apk_file}[/bold red]", title="Chimera Intel | Defensive", border_style="red"))
    api_key = API_KEYS.mobsf_api_key
    if not api_key:
        console.print("[bold red]Error:[/] MOBSF_API_KEY not found in .env file.")
        raise typer.Exit(code=1)
    
    results = analyze_apk_mobsf(apk_file, mobsf_url, api_key)
    save_or_print_results(results, output_file)
    save_scan_to_db(target=os.path.basename(apk_file), module="defensive_mobsf", data=results)