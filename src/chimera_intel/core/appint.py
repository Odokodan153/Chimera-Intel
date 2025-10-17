"""
Module for Mobile Application Intelligence (APPINT).

Provides tools for static and dynamic analysis of mobile application files
to uncover hardcoded secrets, insecure code practices, and other vulnerabilities.
"""

import typer
import logging
import subprocess
import os
import shutil
import re
from typing import Optional, List

from .schemas import StaticAppAnalysisResult, FoundSecret
from .utils import save_or_print_results, console
from .database import save_scan_to_db

logger = logging.getLogger(__name__)


def analyze_apk_static(file_path: str) -> StaticAppAnalysisResult:
    """
    Performs static analysis on an APK file by decompiling it and searching for secrets.

    NOTE: This function requires 'apktool' to be installed and in the system's PATH.

    Args:
        file_path (str): The path to the .apk file to analyze.

    Returns:
        StaticAppAnalysisResult: A Pydantic model with the analysis results.
    """
    if not os.path.exists(file_path):
        return StaticAppAnalysisResult(file_path=file_path, error="APK file not found.")
    output_dir = f"{file_path}_decompiled"

    try:
        # 1. Decompile the APK using apktool

        console.print(f"[cyan]Decompiling {os.path.basename(file_path)}...[/cyan]")
        subprocess.run(
            ["apktool", "d", file_path, "-o", output_dir],
            check=True,
            capture_output=True,
            text=True,
        )

        # 2. Search for hardcoded secrets

        console.print("[cyan]Searching for hardcoded secrets...[/cyan]")
        secrets: List[FoundSecret] = []
        secret_pattern = re.compile(
            r'(api_key|secret|token|password)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_./-]{10,})["\']?',
            re.IGNORECASE,
        )

        for root, _, files in os.walk(output_dir):
            for file in files:
                if file.endswith((".xml", ".java", ".kt", ".smali")):
                    file_path_full = os.path.join(root, file)
                    with open(
                        file_path_full, "r", encoding="utf-8", errors="ignore"
                    ) as f:
                        for line_num, line in enumerate(f, 1):
                            match = secret_pattern.search(line)
                            if match:
                                secrets.append(
                                    FoundSecret(
                                        file_path=os.path.relpath(
                                            file_path_full, output_dir
                                        ),
                                        line_number=line_num,
                                        rule_id="generic-secret",
                                        secret_type=match.group(1),
                                    )
                                )
        return StaticAppAnalysisResult(file_path=file_path, secrets_found=secrets)
    except FileNotFoundError:
        return StaticAppAnalysisResult(
            file_path=file_path, error="apktool not found. Please install it."
        )
    except subprocess.CalledProcessError as e:
        return StaticAppAnalysisResult(
            file_path=file_path, error=f"apktool failed: {e.stderr}"
        )
    except Exception as e:
        return StaticAppAnalysisResult(
            file_path=file_path, error=f"An unexpected error occurred: {e}"
        )
    finally:
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)


appint_app = typer.Typer()


@appint_app.command("static")
def run_static_apk_analysis(
    file_path: str = typer.Argument(..., help="Path to the .apk file to analyze."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Performs static analysis on an Android APK file.
    """
    try:
        results_model = analyze_apk_static(file_path)
        if results_model.error:
            console.print(f"[red]Static analysis failed: {results_model.error}[/red]")
            raise typer.Exit(code=1)

        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        save_scan_to_db(
            target=os.path.basename(file_path),
            module="appint_static",
            data=results_dict,
        )
    except Exception as e:
        console.print(f"[red]An unexpected error occurred: {e}[/red]")
        raise typer.Exit(code=1)
