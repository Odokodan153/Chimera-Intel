"""
Module for internal analysis, incident response, and forensics.

This module provides tools to analyze data from within a network or from
a compromised system, such as log files, malware samples, and forensic artifacts.
"""

import typer
import logging
import hashlib
import re
import os
import csv
from typing import Optional, List, Dict

try:
    import analyzeMFT  # type: ignore

    MFT_AVAILABLE = True
except ImportError:
    analyzeMFT = None
    MFT_AVAILABLE = False
from .schemas import (
    LogAnalysisResult,
    StaticAnalysisResult,
    MFTAnalysisResult,
    MFTEntry,
)
from .utils import save_or_print_results

logger = logging.getLogger(__name__)

# --- Incident Response ---


def analyze_log_file(file_path: str) -> LogAnalysisResult:
    """
    Parses a log file to extract and flag suspicious events using basic pattern matching.
    """
    logger.info(f"Analyzing log file: {file_path}")

    if not os.path.exists(file_path):
        error_msg = f"Log file not found at path: {file_path}"
        logger.error(error_msg)
        return LogAnalysisResult(
            total_lines_parsed=0, suspicious_events={}, error=error_msg
        )
    suspicious_patterns = {
        "failed_login": re.compile(
            r"(fail(ed|ure) login|authentication failure|Failed password)",
            re.IGNORECASE,
        ),
        "ssh_bruteforce": re.compile(
            r"ssh.*(authentication failure|invalid user|disconnect)", re.IGNORECASE
        ),
        "error_spike": re.compile(r"error|critical|fatal", re.IGNORECASE),
    }

    suspicious_events: Dict[str, int] = {key: 0 for key in suspicious_patterns}
    lines_parsed = 0

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                lines_parsed += 1
                for event, pattern in suspicious_patterns.items():
                    if pattern.search(line):
                        suspicious_events[event] += 1
        return LogAnalysisResult(
            total_lines_parsed=lines_parsed,
            suspicious_events=suspicious_events,
        )
    except Exception as e:
        error_msg = f"Failed to read or analyze log file: {e}"
        logger.error(error_msg)
        return LogAnalysisResult(
            total_lines_parsed=0, suspicious_events={}, error=error_msg
        )


# --- Malware Analysis ---


def perform_static_analysis(file_path: str) -> StaticAnalysisResult:
    """
    Performs basic static analysis on a given file without executing it.
    It calculates file hashes and extracts potential human-readable strings.
    """
    logger.info(f"Performing static analysis on: {file_path}")

    if not os.path.exists(file_path):
        error_msg = f"File not found for static analysis: {file_path}"
        logger.error(error_msg)
        return StaticAnalysisResult(filename=file_path, file_size=0, error=error_msg)
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        file_size = len(content)
        hashes = {
            "md5": hashlib.md5(content).hexdigest(),
            "sha1": hashlib.sha1(content).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
        }

        string_pattern = re.compile(rb'[A-Za-z0-9\s.,!?:;"\'/\\-_{}]{5,}')
        found_strings = [
            s.decode("utf-8", "ignore") for s in string_pattern.findall(content)
        ]

        return StaticAnalysisResult(
            filename=os.path.basename(file_path),
            file_size=file_size,
            hashes=hashes,
            embedded_strings=list(set(found_strings))[:100],
        )
    except Exception as e:
        error_msg = f"Failed during static analysis of {file_path}: {e}"
        logger.error(error_msg)
        return StaticAnalysisResult(filename=file_path, file_size=0, error=error_msg)


# --- Forensic Artifact Analysis ---


def parse_mft(file_path: str) -> MFTAnalysisResult:
    """
    Parses a Master File Table ($MFT) to create a timeline of file activity
    using the 'analyzeMFT' library.
    """
    logger.info(f"Attempting to parse MFT file: {file_path}")

    if not MFT_AVAILABLE or not analyzeMFT:
        error_msg = "'analyzeMFT' library not installed. Please add it to pyproject.toml and reinstall."
        logger.error(error_msg)
        return MFTAnalysisResult(total_records=0, entries=[], error=error_msg)
    if not os.path.exists(file_path):
        error_msg = f"MFT file not found at path: {file_path}"
        logger.error(error_msg)
        return MFTAnalysisResult(total_records=0, entries=[], error=error_msg)
    entries: List[MFTEntry] = []
    dummy_output = "mft_temp_output.csv"
    try:
        analyzeMFT.main(filename=file_path, output_filename=dummy_output)

        with open(dummy_output, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entries.append(
                    MFTEntry(
                        record_number=int(row.get("Record Number", -1)),
                        filename=row.get("Filename", "N/A"),
                        creation_time=row.get("Created", "N/A"),
                        modification_time=row.get("Last Modified", "N/A"),
                        is_directory=row.get("is_directory", "false").lower() == "true",
                    )
                )
        return MFTAnalysisResult(total_records=len(entries), entries=entries)
    except Exception as e:
        error_msg = f"An unexpected error occurred during MFT parsing: {e}"
        logger.error(error_msg)
        return MFTAnalysisResult(total_records=0, entries=[], error=error_msg)
    finally:
        if os.path.exists(dummy_output):
            os.remove(dummy_output)


# --- Typer CLI Application ---


internal_app = typer.Typer()


@internal_app.command("analyze-log")
def run_log_analysis(
    file_path: str = typer.Argument(..., help="Path to the log file to analyze."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Parses log files for suspicious activities."""
    results = analyze_log_file(file_path)
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)


@internal_app.command("static-analysis")
def run_static_analysis(
    file_path: str = typer.Argument(..., help="Path to the file for static analysis."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Performs static analysis on a file to extract hashes and strings."""
    results = perform_static_analysis(file_path)
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)


@internal_app.command("parse-mft")
def run_mft_parsing(
    file_path: str = typer.Argument(..., help="Path to the $MFT file to parse."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Parses a Master File Table to reconstruct file activity."""
    results = parse_mft(file_path)
    results_dict = results.model_dump()
    save_or_print_results(results_dict, output_file)
