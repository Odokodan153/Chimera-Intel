import typer
import os
import requests
import json
import subprocess
import shodan
import time

from rich.console import Console
from rich.panel import Panel
from rich.json import JSON
from rich.progress import Progress

console = Console()

# --- Existing Functions (HIBP, GitHub, DNSTwist, Shodan) ---
# (These functions remain the same as in the previous file)

def check_hibp_breaches(domain: str, api_key: str) -> dict:
    """Checks a domain against the Have I Been Pwned (HIBP) database."""
    if not api_key:
        return {"error": "HIBP API key not found."}
    url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
    headers = {"hibp-api-key": api_key, "user-agent": "Chimera-Intel-Tool"}
    try:
        response = requests.get(url)
        if response.status_code == 404:
            return {"breaches": [], "message": "No breaches found for this domain."}
        response.raise_for_status()
        return {"breaches": response.json()}
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            return {"error": "Authentication error. Check your HIBP API key."}
        return {"error": f"HTTP error: {e.response.status_code} {e.response.reason}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}

def search_github_leaks(query: str, api_key: str) -> dict:
    """Searches GitHub for potential secret leaks related to a query (e.g., company domain)."""
    if not api_key:
        return {"error": "GitHub Personal Access Token not found."}
    url = f"https://api.github.com/search/code?q={query}"
    headers = {"Authorization": f"token {api_key}"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        items = [{"url": item.get("html_url"), "repository": item.get("repository", {}).get("full_name")} for item in data.get("items", [])]
        return {"total_count": data.get("total_count"), "items": items}
    except Exception as e:
        return {"error": f"An unexpected error occurred with GitHub search: {e}"}

def find_typosquatting_dnstwist(domain: str) -> dict:
    """Uses the dnstwist command-line tool to find potential typosquatting domains."""
    try:
        process = subprocess.run(["dnstwist", "--json", domain], capture_output=True, text=True, check=True)
        return json.loads(process.stdout)
    except FileNotFoundError:
        return {"error": "dnstwist command not found. Please ensure it is installed and in your PATH."}
    except subprocess.CalledProcessError as e:
        return {"error": f"dnstwist returned an error: {e.stderr}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred while running dnstwist: {e}"}

def analyze_attack_surface_shodan(query: str, api_key: str) -> dict:
    """Uses Shodan to find devices and services exposed on the internet."""
    if not api_key:
        return {"error": "Shodan API key not found."}
    try:
        api = shodan.Shodan(api_key)
        results = api.search(query, limit=100)
        hosts = []
        for service in results.get('matches', []):
            hosts.append({
                "ip": service.get('ip_str'),
                "port": service.get('port'),
                "organization": service.get('org'),
                "hostnames": service.get('hostnames'),
                "data": service.get('data', '').strip()
            })
        return {"total_results": results.get('total', 0), "hosts": hosts}
    except Exception as e:
        return {"error": f"An error occurred with Shodan: {e}"}


# --- NEW Advanced Defensive Functions ---

def search_pastebin_psbdmp(query: str) -> dict:
    """Searches Pastebin dumps for a specific query using the psbdmp tool."""
    try:
        # psbdmp -q "query" -j 
        process = subprocess.run(
            ["psbdmp", "-q", query, "-j"],
            capture_output=True, text=True, check=True
        )
        # psbdmp returns JSON objects on each line, so we need to parse them.
        pastes = [json.loads(line) for line in process.stdout.strip().split('\n') if line]
        return {"pastes": pastes, "count": len(pastes)}
    except FileNotFoundError:
        return {"error": "psbdmp command not found. Please ensure it is installed (`pip install psbdmp`)."}
    except subprocess.CalledProcessError as e:
        # If no results are found, it might exit with an error, handle this gracefully.
        return {"pastes": [], "message": f"psbdmp returned an error (or no results found): {e.stderr}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred while running psbdmp: {e}"}

def analyze_ssl_ssllabs(host: str) -> dict:
    """Performs an in-depth SSL/TLS analysis using the SSL Labs API."""
    api_url = "https://api.ssllabs.com/api/v3/"
    
    def start_scan(hostname):
        """Initiates a new scan."""
        payload = {'host': hostname, 'startNew': 'on', 'all': 'done'}
        response = requests.get(api_url + "analyze", params=payload)
        response.raise_for_status()
        return response.json()

    def poll_scan(hostname):
        """Polls for the scan results."""
        payload = {'host': hostname, 'all': 'done'}
        while True:
            response = requests.get(api_url + "analyze", params=payload)
            response.raise_for_status()
            data = response.json()
            if data['status'] in ('READY', 'ERROR'):
                return data
            # Respect SSL Labs' advice to wait
            time.sleep(10)
    
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

def analyze_apk_mobsf(file_path: str, mobsf_url: str, api_key: str) -> dict:
    """Uploads an APK to a running MobSF instance and retrieves the scan results."""
    if not os.path.exists(file_path):
        return {"error": f"File not found at path: {file_path}"}
    if not mobsf_url or not api_key:
        return {"error": "MobSF URL and API Key are required."}
        
    headers = {'Authorization': api_key}
    
    try:
        # Step 1: Upload the file
        console.print(" [cyan]>[/cyan] Uploading APK to MobSF...")
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            upload_response = requests.post(f"{mobsf_url}/api/v1/upload", headers=headers, files=files)
            upload_response.raise_for_status()
        upload_data = upload_response.json()
        
        # Step 2: Start the scan
        console.print(" [cyan]>[/cyan] Starting MobSF scan...")
        scan_response = requests.post(f"{mobsf_url}/api/v1/scan", headers=headers, data=upload_data)
        scan_response.raise_for_status()
        
        # Step 3: Get the JSON report
        # In a real scenario, you might need to wait, but for now we fetch it immediately
        console.print(" [cyan]>[/cyan] Fetching MobSF JSON report...")
        report_response = requests.post(f"{mobsf_url}/api/v1/report_json", headers=headers, data=upload_data)
        report_response.raise_for_status()
        
        return report_response.json()
    except Exception as e:
        return {"error": f"An error occurred with MobSF API: {e}"}


# --- Typer CLI Application for this module ---

defensive_app = typer.Typer()

@defensive_app.command("breaches")
def run_breach_check(domain: str = typer.Argument(..., help="Your company's domain to check for breaches.")):
    """Checks your domain against the Have I Been Pwned database."""
    console.print(Panel(f"[bold blue]Checking for Breaches at {domain}[/bold blue]", border_style="red"))
    api_key = os.getenv("HIBP_API_KEY")
    results = check_hibp_breaches(domain, api_key)
    console.print(JSON(json.dumps(results, indent=4)))

@defensive_app.command("leaks")
def run_leaks_check(query: str = typer.Argument(..., help="Search query, e.g., 'yourcompany.com password'")):
    """Searches GitHub for potential code and secret leaks."""
    console.print(Panel(f"[bold blue]Searching GitHub for leaks: '{query}'[/bold blue]", border_style="red"))
    api_key = os.getenv("GITHUB_PAT")
    results = search_github_leaks(query, api_key)
    console.print(JSON(json.dumps(results, indent=4)))

@defensive_app.command("typosquat")
def run_typosquat_check(domain: str = typer.Argument(..., help="Your company's domain to check for typosquatting.")):
    """Finds potential phishing domains similar to yours using dnstwist."""
    console.print(Panel(f"[bold blue]Checking for Typosquatting Domains for {domain}[/bold blue]", border_style="red"))
    results = find_typosquatting_dnstwist(domain)
    console.print(JSON(json.dumps(results, indent=4)))

@defensive_app.command("surface")
def run_surface_check(query: str = typer.Argument(..., help="Shodan search query, e.g., 'org:\"My Company\"'")):
    """Analyzes your public attack surface using Shodan."""
    console.print(Panel(f"[bold blue]Analyzing Attack Surface with Shodan: '{query}'[/bold blue]", border_style="red"))
    api_key = os.getenv("SHODAN_API_KEY")
    results = analyze_attack_surface_shodan(query, api_key)
    console.print(JSON(json.dumps(results, indent=4, default=str)))

# --- NEW Commands for Advanced Functions ---

@defensive_app.command("pastebin")
def run_pastebin_check(query: str = typer.Argument(..., help="Keyword or domain to search for in Pastebin dumps.")):
    """Searches Pastebin dumps using psbdmp."""
    console.print(Panel(f"[bold blue]Searching Pastebin for: '{query}'[/bold blue]", border_style="red"))
    results = search_pastebin_psbdmp(query)
    console.print(JSON(json.dumps(results, indent=4)))

@defensive_app.command("ssllabs")
def run_ssllabs_check(domain: str = typer.Argument(..., help="The domain to run an SSL Labs analysis on.")):
    """Performs an in-depth SSL/TLS analysis via SSL Labs."""
    console.print(Panel(f"[bold blue]Starting full SSL/TLS analysis for {domain}[/bold blue]", border_style="red"))
    results = analyze_ssl_ssllabs(domain)
    console.print(JSON(json.dumps(results, indent=4)))

@defensive_app.command("mobsf")
def run_mobsf_scan(
    apk_file: str = typer.Option(..., "--apk-file", help="Path to the .apk file to be analyzed."),
    mobsf_url: str = typer.Option("http://127.0.0.1:8000", help="URL of your running MobSF instance."),
):
    """Analyzes an Android .apk file using a local MobSF instance."""
    console.print(Panel(f"[bold blue]Analyzing mobile app: {apk_file}[/bold blue]", border_style="red"))
    api_key = os.getenv("MOBSF_API_KEY") # You must get this from your MobSF instance
    if not api_key:
        console.print("[bold red]Error:[/] MOBSF_API_KEY not found in .env file.")
        raise typer.Exit(code=1)
    
    results = analyze_apk_mobsf(apk_file, mobsf_url, api_key)
    console.print(JSON(json.dumps(results, indent=4)))