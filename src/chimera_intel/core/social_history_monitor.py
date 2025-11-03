"""
Social Media History Monitor for Chimera Intel.

Tracks changes to public social media profiles without using APIs.

Requires:
- requests
- beautifulsoup4
- difflib
"""

import typer
import os
import requests
import difflib
import logging
from typing import Optional
from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.schemas import ProfileChangeResult

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

logger = logging.getLogger(__name__)

# Directory to store the last-known state of profiles
PROFILE_DB_PATH = "models/profile_history"

def _get_profile_text(url: str) -> Optional[str]:
    """Fetches a URL and extracts all visible text."""
    if not BS4_AVAILABLE:
        raise ImportError("Missing 'beautifulsoup4'. Please run: pip install beautifulsoup4")
        
    try:
        # Use a common user-agent to avoid simple blocks
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove script and style elements
        for script_or_style in soup(["script", "style"]):
            script_or_style.decompose()
            
        # Get text, strip whitespace, and join lines
        text = ' '.join(soup.stripped_strings)
        return text
    except requests.RequestException as e:
        logger.error(f"Error fetching profile URL {url}: {e}")
        return None

def monitor_profile_changes(profile_url: str, target_name: str) -> ProfileChangeResult:
    """
    Checks a public profile for changes against its last known state.
    
    Args:
        profile_url: The full URL of the public profile to monitor.
        target_name: A unique name for the target (used for the filename).
    """
    if not BS4_AVAILABLE:
        return ProfileChangeResult(profile_url=profile_url, error="Missing 'beautifulsoup4' library.")

    os.makedirs(PROFILE_DB_PATH, exist_ok=True)
    
    # Sanitize target_name for filename
    safe_filename = "".join(c for c in target_name if c.isalnum() or c in ('_','-')).rstrip()
    if not safe_filename:
        safe_filename = str(hash(profile_url)) # Fallback
        
    db_file_path = os.path.join(PROFILE_DB_PATH, f"{safe_filename}.txt")
    
    result = ProfileChangeResult(profile_url=profile_url)
    
    # 1. Get current profile text
    current_text = _get_profile_text(profile_url)
    if current_text is None:
        result.error = "Failed to fetch or parse profile URL."
        return result
    
    current_text_lines = current_text.split() # Split by space for diffing

    # 2. Get old profile text, if it exists
    if not os.path.exists(db_file_path):
        # This is the first time seeing this profile
        with open(db_file_path, "w", encoding="utf-8") as f:
            f.write(current_text)
        result.status = "Initial profile state saved."
        return result

    with open(db_file_path, "r", encoding="utf-8") as f:
        old_text = f.read()
    old_text_lines = old_text.split()
    
    # 3. Compare (diff) the two versions
    diff = difflib.unified_diff(old_text_lines, current_text_lines, fromfile="Previous", tofile="Current", lineterm='')
    
    diff_lines = list(diff)
    
    if not diff_lines:
        result.status = "No changes detected."
        result.changes_found = False
    else:
        result.status = "Changes detected!"
        result.changes_found = True
        # Store only the actual changes (+ or - lines)
        result.diff_lines = [line for line in diff_lines[2:] if line.startswith('+') or line.startswith('-')]
        
        # 4. Overwrite the old file with the new version for next run
        with open(db_file_path, "w", encoding="utf-8") as f:
            f.write(current_text)
            
    return result

# --- CLI Application ---

social_history_app = typer.Typer(
    name="social-history",
    help="Track historical changes to public social media profiles.",
)

@social_history_app.command(
    "monitor",
    help="Check a public profile for text changes since the last run.",
)
def run_monitor_profile(
    url: str = typer.Argument(..., help="The full URL of the public profile."),
    target: str = typer.Option(..., "--target", "-t", help="A unique name for this target (e.g., 'john_doe_twitter')."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    CLI command to monitor a profile for changes.
    """
    if not BS4_AVAILABLE:
        console.print("[bold red]Error: 'beautifulsoup4' library is required.[/bold red]")
        console.print("Please run: pip install beautifulsoup4")
        raise typer.Exit(code=1)
        
    console.print(f"[cyan]Monitoring profile for changes:[/cyan] {url}")
    result = monitor_profile_changes(url, target)
    
    if result.changes_found:
        console.print("[bold yellow]Changes detected![/bold yellow]")
        for line in result.diff_lines:
            if line.startswith('+'):
                console.print(f"[green]{line}[/green]")
            elif line.startswith('-'):
                console.print(f"[red]{line}[/red]")
    elif result.error:
        console.print(f"[bold red]Error:[/bold red] {result.error}")
    else:
        console.print(f"[green]{result.status}[/green]")
        
    save_or_print_results(result.model_dump(), output_file, print_to_console=(not result.changes_found))