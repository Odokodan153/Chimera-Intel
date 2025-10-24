"""
Software Supply Chain Security (SCAINT) Module for Chimera Intel.
"""

import typer
import git
import os
import tempfile
import subprocess
import json
# import sys  # <-- FIX: Removed sys import

# Create a new Typer application for SCAINT commands
scaint_app = typer.Typer(
    name="scaint",
    help="Software Supply Chain Security (SCAINT)",
)


def analyze_dependencies(repo_path: str) -> dict:
    """
    Analyzes the dependencies in a given repository path using OSV-Scanner.
    """
    requirements_path = os.path.join(repo_path, "requirements.txt")
    if not os.path.exists(requirements_path):
        raise FileNotFoundError("requirements.txt not found in the repository.")
    # Run osv-scanner and capture the JSON output
    result = subprocess.run(
        ["osv-scanner", "-r", repo_path, "--json"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 and result.stderr:
        # OSV-Scanner prints non-vulnerability related errors to stderr
        # and vulnerability findings to stdout, so we check stderr first
        raise Exception(f"OSV-Scanner error: {result.stderr}")
    return json.loads(result.stdout) if result.stdout else {"results": []}


@scaint_app.command(
    name="analyze-repo",
    help="Analyze a public code repository for supply chain vulnerabilities.",
)
def analyze_repo(
    repo_url: str = typer.Argument(
        ...,
        help="The URL of the public Git repository to analyze.",
    ),
):
    """
    Clones a public Git repository, identifies its dependencies, and scans
    them for known vulnerabilities and license issues.
    """
    print(f"Analyzing repository: {repo_url}")

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # 1. Clone the repository into a temporary directory
            print(f"Cloning repository into: {tmpdir}")
            git.Repo.clone_from(repo_url, tmpdir)

            # 2. Analyze the dependencies for vulnerabilities
            print("Scanning for known vulnerabilities...")
            vulnerabilities = analyze_dependencies(tmpdir)

            # 3. Display the results
            if vulnerabilities and vulnerabilities.get("results"):
                print("\n--- Vulnerability Scan Results ---")
                for result in vulnerabilities["results"]:
                    for pkg in result.get("packages", []):
                        print(
                            f"\nPackage: {pkg['package']['name']}@{pkg['package']['version']}"
                        )
                        for vuln in pkg.get("vulnerabilities", []):
                            print(f"  - ID: {vuln['id']}")
                            print(f"    Summary: {vuln['summary']}")
                            print(f"    Severity: {vuln.get('severity', 'N/A')}")
                print("---------------------------------")
            else:
                print("\nNo known vulnerabilities found in the dependencies.")
            
            # FIX: Removed 'raise typer.Exit(code=0)'.
            # CliRunner interprets a normal return as exit code 0.
        
        except git.exc.GitCommandError as e:
            print(f"Error cloning repository: {e}")
            # FIX: Use typer.Exit(code=1) for errors.
            raise typer.Exit(code=1)
        except FileNotFoundError as e:
            print(f"Analysis Error: {e}")
            # FIX: Use typer.Exit(code=1) for errors.
            raise typer.Exit(code=1)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            # FIX: Use typer.Exit(code=1) for errors.
            raise typer.Exit(code=1)


if __name__ == "__main__":
    scaint_app()