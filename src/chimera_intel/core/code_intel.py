"""
Module for Code & Repository Intelligence (CODEINT).

Provides tools to:
1. Search public code repositories (GitHub, GitLab) for leaked credentials
   and sensitive information.
2. Clone and analyze public repositories to extract intelligence on
   committers and project activity.
"""

import typer
import logging
import git  # type: ignore
import tempfile
import shutil
import os
import httpx
import concurrent.futures
from collections import Counter
from typing import Optional, List, Dict, Any, Counter as CounterType, Set
from urllib.parse import quote
from rich.console import Console
from rich.progress import Progress

from .schemas import (
    RepoAnalysisResult,
    CommitterInfo,
    GitHubLeaksResult,
    GitHubLeakItem,
    GitLabLeaksResult,
    GitLabLeakItem
)
from .utils import save_or_print_results
from .database import save_scan_to_db
from .config_loader import API_KEYS
from .http_client import sync_client

logger = logging.getLogger(__name__)
console = Console()

# --- Repository Analysis (Cloning) ---

def analyze_git_repository(repo_url: str) -> RepoAnalysisResult:
    """
    Clones a public Git repository to a temporary directory and analyzes its history.

    Args:
        repo_url (str): The URL of the Git repository to analyze.

    Returns:
        RepoAnalysisResult: A Pydantic model with the analysis results.
    """
    temp_dir = tempfile.mkdtemp()
    logger.info(f"Cloning repository {repo_url} into temporary directory {temp_dir}")

    try:
        # Clone the repository
        repo = git.Repo.clone_from(
            repo_url, temp_dir, depth=100
        )  # Limit depth for performance

        commits = list(repo.iter_commits("main"))

        # 1. Committer Analysis
        committer_counts = Counter(
            (commit.author.name, commit.author.email)
            for commit in commits
            if commit.author
        )
        top_committers = [
            CommitterInfo(
                name=author[0] or "Unknown",
                email=author[1] or "Unknown",
                commit_count=count,
            )
            for author, count in committer_counts.most_common(5)
        ]

        # 2. Commit Keyword Analysis
        keyword_counts: CounterType[str] = Counter()
        keywords = ["feature", "fix", "bug", "refactor", "security", "release", "feat"]
        for commit in commits:
            message = commit.message.lower()
            for keyword in keywords:
                if keyword in message:
                    keyword_counts[keyword] += 1
                    
        return RepoAnalysisResult(
            repository_url=repo_url,
            total_commits=len(commits),
            total_committers=len(committer_counts),
            top_committers=top_committers,
            commit_keywords=dict(keyword_counts),
        )
    except git.GitCommandError as e:
        # Improved logging per user feedback
        logger.warning(f"Failed to clone or analyze repository {repo_url}: {e}")
        return RepoAnalysisResult(
            repository_url=repo_url,
            total_commits=0,
            total_committers=0,
            error=f"Git command failed (repo may be private or deleted): {e}",
        )
    except Exception as e:
        logger.error(f"An unexpected error occurred analyzing {repo_url}: {e}")
        return RepoAnalysisResult(
            repository_url=repo_url,
            total_commits=0,
            total_committers=0,
            error=f"An unexpected error occurred: {e}",
        )
    finally:
        # Clean up the temporary directory
        if os.path.exists(temp_dir):
            logger.debug(f"Cleaning up temporary directory: {temp_dir}")
            shutil.rmtree(temp_dir)

# --- Code Leak Search (API) ---

def search_github_leaks(
    keywords: List[str], org_name: Optional[str] = None
) -> GitHubLeaksResult:
    """
    Searches GitHub code for specific keywords, optionally scoped to an organization.
    """
    api_key = API_KEYS.github_pat
    if not api_key:
        return GitHubLeaksResult(error="GITHUB_PAT not found in .env file.")

    base_url = "https://api.github.com/search/code"
    headers = {
        "Authorization": f"token {api_key}",
        "Accept": "application/vnd.github.v3.text-match+json",
    }
    
    # Build search query
    query = " ".join([f'"{part}"' for part in keywords])
    if org_name:
        query += f" org:{org_name}"
        
    params = {"q": query, "per_page": 50}
    
    logger.info(f"Searching GitHub code with query: {query}")

    try:
        response = sync_client.get(base_url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        
        items = [
            GitHubLeakItem.model_validate(item) for item in data.get("items", [])
        ]
        
        return GitHubLeaksResult(
            total_count=data.get("total_count", 0),
            items=items
        )
    # Handle rate limiting per user feedback
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 403 or e.response.status_code == 429:
            logger.error(f"GitHub API rate limit hit. Check your GITHUB_PAT. {e}")
            return GitHubLeaksResult(error="GitHub API rate limit exceeded.")
        logger.error(f"Failed to search GitHub: {e}")
        return GitHubLeaksResult(error=f"An API error occurred: {e}")
    except Exception as e:
        logger.error(f"Failed to search GitHub: {e}")
        return GitHubLeaksResult(error=f"An unexpected error occurred: {e}")

def _get_gitlab_group_id(group_name: str, api_key: str) -> Optional[int]:
    """Helper to find a GitLab group's numeric ID from its name."""
    url = f"https://gitlab.com/api/v4/groups?search={quote(group_name)}"
    headers = {"PRIVATE-TOKEN": api_key}
    try:
        response = sync_client.get(url, headers=headers)
        response.raise_for_status()
        groups = response.json()
        if groups:
            # Assume first match is correct
            return groups[0].get("id")
    except Exception as e:
        logger.error(f"Failed to resolve GitLab group ID for '{group_name}': {e}")
    return None

def search_gitlab_leaks(
    keywords: List[str], group_name: Optional[str] = None
) -> GitLabLeaksResult:
    """
    Searches GitLab code for specific keywords, optionally scoped to a group.
    """
    api_key = API_KEYS.gitlab_pat
    if not api_key:
        return GitLabLeaksResult(error="GITLAB_PAT not found in .env file.")

    headers = {"PRIVATE-TOKEN": api_key}
    
    # GitLab search query is a single string
    query = " ".join(keywords)
    params = {"scope": "blobs", "search": query, "per_page": 50}
    
    base_url = "https://gitlab.com/api/v4/search"
    
    if group_name:
        logger.info(f"Resolving group ID for GitLab group: {group_name}")
        group_id = _get_gitlab_group_id(group_name, api_key)
        if group_id:
            # Use the group-specific search endpoint
            base_url = f"https://gitlab.com/api/v4/groups/{group_id}/search"
            logger.info(f"Searching GitLab group '{group_name}' (ID: {group_id}) for: {query}")
        else:
            logger.warning(f"Could not find group '{group_name}'. Searching all of GitLab.")
            logger.info(f"Searching all of GitLab for: {query}")
    else:
        logger.info(f"Searching all of GitLab for: {query}")

    try:
        response = sync_client.get(base_url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        
        items = [GitLabLeakItem.model_validate(item) for item in data]
        
        return GitLabLeaksResult(
            total_count=len(items), # GitLab total is in headers, this is just page count
            items=items
        )
    # Handle rate limiting per user feedback
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 403 or e.response.status_code == 429:
            logger.error(f"GitLab API rate limit hit. Check your GITLAB_PAT. {e}")
            return GitLabLeaksResult(error="GitLab API rate limit exceeded.")
        logger.error(f"Failed to search GitLab: {e}")
        return GitLabLeaksResult(error=f"An API error occurred: {e}")
    except Exception as e:
        logger.error(f"Failed to search GitLab: {e}")
        return GitLabLeaksResult(error=f"An unexpected error occurred: {e}")

# --- Typer CLI Application ---

code_intel_app = typer.Typer(
    name="code",
    help="Code Intelligence (CODEINT) tools for public repositories."
)

@code_intel_app.command("analyze-repo")
def analyze_repo(
    repo_url: str = typer.Argument(
        ..., help="The full URL of the public Git repository."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Analyzes a public Git repository for committer and activity intelligence."""
    console.print(f"Analyzing repository: {repo_url}")
    results_model = analyze_git_repository(repo_url)

    if results_model.error:
        console.print(
            f"[bold red]Error:[/bold red] Failed to clone or analyze repository: {results_model.error}"
        )
        raise typer.Exit(code=1)

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=repo_url, module="code_intel_repo", data=results_dict)

@code_intel_app.command("github-search")
def run_github_search(
    keywords: List[str] = typer.Option(
        ...,
        "--keyword",
        "-k",
        help="A keyword to search for (e.g., 'api_key', 'password'). Can be used multiple times."
    ),
    org_name: Optional[str] = typer.Option(
        None,
        "--org",
        "-o",
        help="An optional GitHub organization to scope the search to."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-O", help="Save results to a JSON file."
    ),
):
    """
    Searches GitHub code for keyword matches.
    """
    try:
        results_model = search_github_leaks(keywords, org_name)
        if results_model.error:
            typer.echo(f"Error: {results_model.error}", err=True)
            raise typer.Exit(code=1)
        
        results_dict = results_model.model_dump(exclude_none=True, by_alias=True)
        save_or_print_results(results_dict, output_file)
        
        target_name = org_name if org_name else "github_global"
        save_scan_to_db(
            target=target_name, module="codeint_github", data=results_dict
        )
    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)

@code_intel_app.command("gitlab-search")
def run_gitlab_search(
    keywords: List[str] = typer.Option(
        ...,
        "--keyword",
        "-k",
        help="A keyword to search for (e.g., 'api_key', 'password'). Can be used multiple times."
    ),
    group_name: Optional[str] = typer.Option(
        None,
        "--group",
        "-g",
        help="An optional GitLab group to scope the search to."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-O", help="Save results to a JSON file."
    ),
):
    """
    Searches GitLab code for keyword matches.
    """
    try:
        results_model = search_gitlab_leaks(keywords, group_name)
        if results_model.error:
            typer.echo(f"Error: {results_model.error}", err=True)
            raise typer.Exit(code=1)
        
        results_dict = results_model.model_dump(exclude_none=True, by_alias=True)
        save_or_print_results(results_dict, output_file)
        
        target_name = group_name if group_name else "gitlab_global"
        save_scan_to_db(
            target=target_name, module="codeint_gitlab", data=results_dict
        )
    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)


# --- NEW COMMAND (Points 1, 4, 5, 6) ---

@code_intel_app.command("analyze-repo-leaks")
def run_analyze_repo_leaks(
    keywords: List[str] = typer.Option(
        ...,
        "--keyword",
        "-k",
        help="A keyword to search for (e.g., 'api_key', 'password'). Can be used multiple times."
    ),
    org_name: Optional[str] = typer.Option(
        None,
        "--org",
        "-o",
        help="An optional GitHub organization to scope the search to."
    ),
    group_name: Optional[str] = typer.Option(
        None,
        "--group",
        "-g",
        help="An optional GitLab group to scope the search to."
    ),
    output_prefix: str = typer.Option(
        "repo_leak_analysis",
        "--output-prefix",
        "-P",
        help="Prefix for the output files (e.g., 'my_scan')."
    ),
    max_workers: int = typer.Option(
        5,
        "--max-workers",
        "-w",
        help="Number of repositories to analyze in parallel."
    )
):
    """
    Finds code leaks on GitHub/GitLab, then analyzes all discovered public repos in parallel.
    
    Saves two files:
    - <output_prefix>_leaks.json: The raw search results from the APIs.
    - <output_prefix>_analysis.json: The committer/activity analysis of each repo.
    """
    console.print("[bold]Step 1: Searching for Code Leaks...[/bold]")
    
    all_repo_urls: Set[str] = set()
    all_leak_results = {}
    
    # 1. Search GitHub
    if org_name or keywords: # Only run if search terms are provided
        gh_results = search_github_leaks(keywords, org_name)
        all_leak_results["github"] = gh_results.model_dump(exclude_none=True)
        if gh_results.items:
            for item in gh_results.items:
                # Per user feedback, check if repo is private
                if not item.repository.private:
                    all_repo_urls.add(item.repository.html_url)
                else:
                    logger.info(f"Skipping private GitHub repo: {item.repository.full_name}")
    
    # 2. Search GitLab
    if group_name or keywords:
        gl_results = search_gitlab_leaks(keywords, group_name)
        all_leak_results["gitlab"] = gl_results.model_dump(exclude_none=True)
        if gl_results.items:
            for item in gl_results.items:
                # Construct the clone URL
                repo_url = f"https://gitlab.com/{item.project_path}.git"
                all_repo_urls.add(repo_url)

    # 3. Save leak results (per user feedback)
    leaks_output_file = f"{output_prefix}_leaks.json"
    save_or_print_results(all_leak_results, leaks_output_file, print_to_console=False)
    console.print(f"[green]Leak search results saved to: {leaks_output_file}[/green]")
    
    if not all_repo_urls:
        console.print("[yellow]No public repositories found containing leaks. Analysis complete.[/yellow]")
        raise typer.Exit()

    console.print(f"\n[bold]Step 2: Analyzing {len(all_repo_urls)} unique public repositories in parallel...[/bold]")
    
    analysis_results: List[Dict[str, Any]] = []
    
    # 4. Analyze repos in parallel (per user feedback)
    with Progress(console=console) as progress:
        task = progress.add_task("[cyan]Analyzing Repos...", total=len(all_repo_urls))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(analyze_git_repository, url): url for url in all_repo_urls
            }
            
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result_model = future.result()
                    result_dict = result_model.model_dump(exclude_none=True)
                    analysis_results.append(result_dict)
                    
                    # Save each analysis to DB individually (per user feedback)
                    save_scan_to_db(
                        target=url,
                        module="code_intel_repo_analysis",
                        data=result_dict
                    )
                    progress.update(task, advance=1)
                except Exception as e:
                    logger.error(f"Error processing result for {url}: {e}")
                    analysis_results.append({"repository_url": url, "error": str(e)})
                    progress.update(task, advance=1)

    # 5. Save analysis results (per user feedback)
    analysis_output_file = f"{output_prefix}_analysis.json"
    save_or_print_results(analysis_results, analysis_output_file, print_to_console=False)
    console.print(f"\n[bold green]Analysis complete! Results saved to: {analysis_output_file}[/bold green]")