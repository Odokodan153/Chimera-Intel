"""
(NEW) OSINT + HUMINT Fusion Hub Module.

Provides functions to process structured OSINT (e.g., scraped web data)
and fuse it with the HUMINT network map.
"""

import typer
from typing import List
import json
from pathlib import Path  # <--- (FIX) Import Path
from .utils import console
from .humint import map_network_link
from .schemas import ScrapedJobPosting, ScrapedProfile

osint_app = typer.Typer(
    name="osint-fusion",
    help="Fuses scraped OSINT data into the HUMINT network.",
)

def process_scraped_profiles(profiles: List[ScrapedProfile]) -> int:
    """
    Processes a list of ScrapedProfile objects and fuses them into the network map.
    
    This is the "auto-link" function from the MVP.
    (Implements: OSINT + HUMINT Fusion Hub)
    
    Returns:
        The number of new network links created.
    """
    links_created = 0
    console.print(f"Starting to process {len(profiles)} scraped profiles...")
    
    for profile in profiles:
        person = profile.full_name
        
        # Link 1: Current Employment
        if profile.current_company and profile.current_title:
            relationship = f"Works at as {profile.current_title}"
            company = profile.current_company
            # This calls the real function from humint.py
            map_network_link(person, relationship, company)
            links_created += 1
            
        # Link 2: Past Roles
        for role in profile.past_roles:
            relationship = f"Worked at as {role.get('title', 'Employee')}"
            company = role.get('company')
            if company:
                map_network_link(person, relationship, company)
                links_created += 1
                
        # Link 3: Education
        for school in profile.education:
            map_network_link(person, "Educated at", school)
            links_created += 1
            
    console.print(f"[bold green]Profile processing complete. Created {links_created} new network links.[/bold green]")
    return links_created

def process_scraped_jobs(jobs: List[ScrapedJobPosting]) -> int:
    """
    Processes a list of ScrapedJobPosting objects.
    
    (Implements: Paid Research & Recruiting Signals)
    
    Returns:
        The number of jobs processed.
    """
    console.print(f"Starting to process {len(jobs)} scraped job postings...")
    
    for job in jobs:
        console.print(f"  - [cyan]Signal:[/cyan] {job.company_name} is hiring for '{job.job_title}'.")
        
    console.print(f"[bold green]Job signal processing complete.[/bold green]")
    return len(jobs)


# --- CLI Commands for this module ---

@osint_app.command("fuse-profiles")
def cli_fuse_profiles(
    # (FIX) The type is 'Path', the default value is 'typer.Path(...)'
    json_file: Path = typer.Path(
        exists=True, file_okay=True, dir_okay=False, readable=True
    ),
):
    """
    (NEW) Loads scraped profile data from a JSON file and fuses it.
    
    The JSON file should be a list of objects matching the ScrapedProfile schema.
    """
    try:
        # Pylance was also correct that 'json_file' is a Path object,
        # so we must 'open' it, not pass it directly to json.load()
        with json_file.open('r') as f:
            data = json.load(f)
            
        # Validate data with Pydantic
        profiles = [ScrapedProfile(**item) for item in data]
        
        process_scraped_profiles(profiles)
        
    except json.JSONDecodeError:
        console.print(f"[bold red]Error:[/bold red] File '{json_file}' is not valid JSON.")
    except Exception as e:
        console.print(f"[bold red]Error processing file:[/bold red] {e}")

@osint_app.command("fuse-jobs")
def cli_fuse_jobs(
    # (FIX) The type is 'Path', the default value is 'typer.Path(...)'
    json_file: Path = typer.Path(
        exists=True, file_okay=True, dir_okay=False, readable=True
    ),
):
    """
    (NEW) Loads scraped job posting data from a JSON file.
    
    The JSON file should be a list of objects matching the ScrapedJobPosting schema.
    """
    try:
        # (FIX) Use the .open() method on the Path object
        with json_file.open('r') as f:
            data = json.load(f)
            
        # Validate data with Pydantic
        jobs = [ScrapedJobPosting(**item) for item in data]
        
        process_scraped_jobs(jobs)
        
    except json.JSONDecodeError:
        console.print(f"[bold red]Error:[/bold red] File '{json_file}' is not valid JSON.")
    except Exception as e:
        console.print(f"[bold red]Error processing file:[/bold red] {e}")