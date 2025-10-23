"""
Module for Code & Repository Intelligence.

Analyzes public Git repositories to extract intelligence on committers,
project activity, and operational security.
"""

import typer
import logging
import git  # type: ignore
import tempfile
import shutil
# --- FIX: Removed 'import sys' ---
from collections import Counter
from typing import Optional, Counter as CounterType
from rich.console import Console
from .schemas import RepoAnalysisResult, CommitterInfo
from .utils import save_or_print_results
from .database import save_scan_to_db

logger = logging.getLogger(__name__)
console = Console()


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
        logger.error(f"Failed to clone or analyze repository {repo_url}: {e}")
        return RepoAnalysisResult(
            repository_url=repo_url,
            total_commits=0,
            total_committers=0,
            error=f"Git command failed: {e}",
        )
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return RepoAnalysisResult(
            repository_url=repo_url,
            total_commits=0,
            total_committers=0,
            error=f"An unexpected error occurred: {e}",
        )
    finally:
        # Clean up the temporary directory

        logger.info(f"Cleaning up temporary directory: {temp_dir}")
        shutil.rmtree(temp_dir)


# --- Typer CLI Application ---


code_intel_app = typer.Typer()


@code_intel_app.command("analyze-repo")
def run_repo_analysis(
    # --- FIX: Changed from positional Argument to named Option ---
    repo_url: str = typer.Option(
        ..., 
        "--repo-url",
        help="The full URL of the public Git repository."
    ),
    # --- End Fix ---
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
        # --- FIX: Use typer.Exit(code=1) for errors ---
        raise typer.Exit(code=1)
        
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)  # Corrected line
    save_scan_to_db(target=repo_url, module="code_intel_repo", data=results_dict)

