"""
Module for real-time monitoring of paste sites (Pastebin, Gist, etc.).

Detects accidental leaks of secrets, configurations, or credentials.
"""

import typer
import logging
import re
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from .schemas import BaseAnalysisResult # Assuming schemas.py has this
from .config_loader import API_KEYS
from .http_client import sync_client
from .utils import save_or_print_results, console
from .database import save_scan_to_db

logger = logging.getLogger(__name__)

# --- Schemas ---
# (Can be moved to schemas.py)

class PasteLeak(BaseModel):
    id: str
    source: str # e.g., "Pastebin", "GitHub Gist"
    url: str
    content_snippet: str
    matched_keyword: str
    leak_type: str # e.g., "API_KEY", "PASSWORD", "CONFIG"

class PasteMonitorResult(BaseAnalysisResult):
    keywords_monitored: List[str]
    leaks_found: List[PasteLeak] = Field(default_factory=list)
    total_leaks: int = 0


# Define common regex patterns for secrets
SECRET_REGEX = {
    "API_KEY": re.compile(r'(xkeys|api_key|secret_key)[\s:="]+[a-zA-Z0-9_-]{20,}', re.IGNORECASE),
    "PASSWORD": re.compile(r'(password|pass|pwd)[\s:="]+[\S]{8,}', re.IGNORECASE),
}

def monitor_paste_sites(keywords: List[str]) -> PasteMonitorResult:
    """
    Scans recent pastes on multiple sites for given keywords and secret patterns.
    (This is a placeholder implementation)
    """
    logger.info(f"Monitoring paste sites for keywords: {keywords}")
    result = PasteMonitorResult(keywords_monitored=keywords)
    
    # In a real implementation, this would use APIs like:
    # 1. Pastebin's scraping API (requires Pro account)
    # 2. GitHub Gist search API (for public gists)
    # 3. Third-party services that aggregate this data
    
    # Placeholder: Mocked data
    mock_paste_content = """
    DB_HOST=prod.db.internal
    DB_USER=admin
    DB_PASSWORD=MySecurePassword123!
    ---
    Our staging api_key is: xkeys-abcdefg1234567890hijklmn
    """
    
    for keyword in keywords:
        if keyword.lower() in mock_paste_content.lower():
            result.leaks_found.append(
                PasteLeak(
                    id="abc123xyz",
                    source="MockPaste",
                    url="https://paste.example.com/abc123xyz",
                    content_snippet=f"...{keyword}...",
                    matched_keyword=keyword,
                    leak_type="KEYWORD"
                )
            )
            
    # Check for regex secrets
    for leak_type, pattern in SECRET_REGEX.items():
        match = pattern.search(mock_paste_content)
        if match:
            result.leaks_found.append(
                PasteLeak(
                    id="abc123xyz",
                    source="MockPaste",
                    url="https://paste.example.com/abc123xyz",
                    content_snippet=f"...{match.group(0)}...",
                    matched_keyword=match.group(0),
                    leak_type=leak_type
                )
            )

    result.total_leaks = len(result.leaks_found)
    return result


# --- Typer CLI Application ---

pastebin_app = typer.Typer(
    name="paste-monitor",
    help="Monitor paste sites for data and credential leaks.",
)

@pastebin_app.command("scan")
def run_paste_scan(
    keywords: List[str] = typer.Argument(..., help="List of keywords to monitor (e.g., 'company.com', 'ProjectChimera')."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Run a one-time scan of recent pastes for keywords and common secrets.
    """
    console.print(f"[bold cyan]Scanning paste sites for keywords:[/bold cyan] {', '.join(keywords)}")
    results_model = monitor_paste_sites(keywords)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    
    if results_model.total_leaks > 0:
        console.print(f"\n[bold red]Warning:[/bold red] Found {results_model.total_leaks} potential leaks.")
        for leak in results_model.leaks_found:
            console.print(f"  - [red][{leak.leak_type}][/red] @ {leak.url} (Keyword: {leak.matched_keyword})")
            
    # Save each leak individually
    for leak in results_model.leaks_found:
        save_scan_to_db(
            target=leak.matched_keyword, 
            module="pastebin_monitor", 
            data=leak.model_dump()
        )