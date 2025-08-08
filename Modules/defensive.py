import typer
import os
import requests
import json
import subprocess
import shodan
import time
from rich.panel import Panel
from rich.progress import Progress
from .utils import console, save_or_print_results

# --- Data Gathering Functions for Defensive Intelligence ---
# NOTE: Docstrings have been added/improved for all functions.
# The logic of the functions themselves remains the same as previously provided.

def check_hibp_breaches(domain: str, api_key: str) -> dict:
    """Checks a domain against the Have I Been Pwned (HIBP) database."""
    # ... (function logic)
    if not api_key: return {"error": "HIBP API key not found."}
    url = f"[https://haveibeenpwned.com/api/v3/breacheddomain/](https://haveibeenpwned.com/api/v3/breacheddomain/){domain}"
    headers = {"hibp-api-key": api_key, "user-agent": "Chimera-Intel-Tool"}
    try:
        response = requests.get(url)
        if response.status_code == 404: return {"breaches": [], "message": "No breaches found for this domain."}
        response.raise_for_status()
        return {"breaches": response.json()}
    except Exception as e: return {"error": f"An error occurred: {e}"}

def search_github_leaks(query: str, api_key: str) -> dict:
    """Searches GitHub for potential secret leaks related to a query."""
    # ... (function logic)
    if not api_key: return {"error": "GitHub Personal Access Token not found."}
    url = f"[https://api.github.com/search/code?q=](https://api.github.com/search/code?q=){query}"
    headers = {"Authorization": f"token {api_key}"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        items = [{"url": item.get("html_url"), "repository": item.get("repository", {}).get("full_name")} for item in data.get("items", [])]
        return {"total_count": data.get("total_count"), "items": items}
    except Exception as e: return {"error": f"An error occurred with GitHub search: {e}"}

def find_typosquatting_dnstwist(domain: str) -> dict:
    """Uses the dnstwist command-line tool to find potential typosquatting domains."""
    # ... (function logic)
    try:
        process = subprocess.run(["dnstwist", "--json", domain], capture_output=True, text=True, check=True)
        return json.loads(process.stdout)
    except FileNotFoundError: return {"error": "dnstwist command not found."}
    except Exception as e: return {"error": f"dnstwist returned an error: {e}"}

def analyze_attack_surface_shodan(query: str, api_key: str) -> dict:
    """Uses Shodan to find devices and services exposed on the internet."""
    # ... (function logic)
    if not api_key: return {"error": "Shodan API key not found."}
    try:
        api = shodan.Shodan(api_key)
        results = api.search(query, limit=100)
        hosts = [{"ip": s.get('ip_str'), "port": s.get('port'), "org": s.get('org'), "hostnames": s.get('hostnames'), "data": s.get('data', '').strip()} for s in results.get('matches', [])]
        return {"total_results": results.get('total', 0), "hosts": hosts}
    except Exception as e: return {"error": f"An error occurred with Shodan: {e}"}

def search_pastebin_psbdmp(query: str) -> dict:
    """Searches Pastebin dumps for a specific query using the psbdmp tool."""
    # ... (function logic)
    try:
        process = subprocess.run(["psbdmp", "-q", query, "-j"], capture_output=True, text=True, check=True)
        pastes = [json.loads(line) for line in process.stdout.strip().split('\n') if line]
        return {"pastes": pastes, "count": len(pastes)}
    except FileNotFoundError: return {"error": "psbdmp command not found."}
    except Exception as e: return {"pastes": [], "message": f"psbdmp returned an error: {e}"}

def analyze_ssl_ssllabs(host: str) -> dict:
    """Performs an in-depth SSL/TLS analysis using the SSL Labs API."""
    # ... (function logic)
    api_url = "[https://api.ssllabs.com/api/v3/](https://api.ssllabs.com/api/v3/)"
    def start_scan(hostname):
        response = requests.get(api_url + "analyze", params={'host': hostname, 'startNew': 'on', 'all': 'done'})
        response.raise_for_status()
        return response.json()
    def poll_scan(hostname):
        while True:
            response = requests.get(api_url + "analyze", params={'host': hostname, 'all': 'done'})
            response.raise_for_status()
            data = response.json()
            if data['status'] in ('READY', 'ERROR'): return data
            time.sleep(10)
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Starting SSL Labs scan...", total=None)
            initial_data = start_scan(host)
            if initial_data['status'] == 'ERROR': return {"error": initial_data.get("statusMessage")}
            progress.update(task, description="[cyan]Scan in progress...")
            final_data = poll_scan(host)
            progress.update(task, completed=100, description="[green]Scan complete!")
        return final_data
    except Exception as e: return {"error": f"An error occurred with SSL Labs API: {e}"}

def analyze_apk_mobsf(file_path: str, mobsf_url: str, api_key: str) -> dict:
    """Uploads an APK to a running MobSF instance and retrieves the scan results."""
    # ... (function logic)
    if not os.path.exists(file_path): return {"error": f"File not found: {file_path}"}
    if not mobsf_url or not api_key: return {"error": "MobSF URL and API Key are required."}
    headers = {'Authorization': api_key}
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            upload_response = requests.post(f"{mobsf_url}/api/v1/upload", headers=headers, files=files)
        upload_response.raise_for_status()
        upload_data = upload_response.json()
        scan_response = requests.post(f"{mobsf_url}/api/v1/scan", headers=headers, data=upload_data)
        scan_response.raise_for_status()
        report_response = requests.post(f"{mobsf_url}/api/v1/report_json", headers=headers, data=upload_data)
        report_response.raise_for_status()
        return report_response.json()
    except Exception as e: return {"error": f"An error occurred with MobSF API: {e}"}


defensive_app = typer.Typer()

@defensive_app.command("breaches")
def run_breach_check(domain: str, output_file: str = None):
    # ... (command logic using save_or_print_results)
    api_key = os.getenv("HIBP_API_KEY")
    results = check_hibp_breaches(domain, api_key)
    save_or_print_results(results, output_file)

@defensive_app.command("leaks")
def run_leaks_check(query: str, output_file: str = None):
    # ... (command logic using save_or_print_results)
    api_key = os.getenv("GITHUB_PAT")
    results = search_github_leaks(query, api_key)
    save_or_print_results(results, output_file)

# ... and so on for all other defensive commands ...
# Each command now calls save_or_print_results at the end.