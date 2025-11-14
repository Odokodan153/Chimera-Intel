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
import sys
from typing import Optional, List, Dict, Any
try:
    import pytsk3
    PYTSK_AVAILABLE = True
except ImportError:
    pytsk3 = None  
    PYTSK_AVAILABLE = False
try:
    from Registry import Registry
    REGISTRY_AVAILABLE = True
except ImportError:
    Registry = None
    REGISTRY_AVAILABLE = False
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
    DigitalArtifact,
    ArtifactExtractionResult,
)
from .utils import save_or_print_results

logger = logging.getLogger(__name__)

# --- Incident Response ---


def analyze_log_file(file_path: str) -> LogAnalysisResult:
    """Parses a log file to extract and flag suspicious events."""
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
    """Performs basic static analysis on a file (hashes + strings)."""
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

        string_pattern = re.compile(rb"[A-Za-z0-9\s.,!?:;\"'/\\-_{}]{5,}")
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
    """Parses a Master File Table ($MFT) to create file activity timeline."""
    logger.info(f"Attempting to parse MFT file: {file_path}")

    if not MFT_AVAILABLE or not analyzeMFT:
        error_msg = "'analyzeMFT' library not installed."
        logger.error(error_msg)
        return MFTAnalysisResult(total_records=0, entries=[], error=error_msg)

    if not os.path.exists(file_path):
        error_msg = f"MFT file not found: {file_path}"
        logger.error(error_msg)
        return MFTAnalysisResult(total_records=0, entries=[], error=error_msg)

    entries: List[MFTEntry] = []
    dummy_output = "mft_temp_output.csv"

    try:
        analyzeMFT.main(filename=file_path, output_filename=dummy_output)

        with open(dummy_output, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if not row:
                    continue
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
        error_msg = f"Unexpected error during MFT parsing: {e}"
        logger.error(error_msg)
        return MFTAnalysisResult(total_records=0, entries=[], error=error_msg)
    finally:
        if os.path.exists(dummy_output):
            os.remove(dummy_output)


# --- Digital Artifact Extraction ---


def _extract_prefetch_files(fs: Any, output_dir: str) -> List[DigitalArtifact]:
    """Helper to extract Prefetch files from Windows."""
    artifacts: List[DigitalArtifact] = []
    if not PYTSK_AVAILABLE:
        logger.warning("pytsk3 not available, skipping prefetch extraction.")
        return artifacts

    try:
        prefetch_dir = fs.open_dir(path="/Windows/Prefetch")
        for f in prefetch_dir:
            name = f.info.name.name.decode("utf-8")
            if name.lower().endswith(".pf"):
                out_path = os.path.join(output_dir, name)
                try:
                    data = f.read_random(0, f.info.meta.size)
                    with open(out_path, "wb") as out_f:
                        out_f.write(data)
                    artifacts.append(
                        DigitalArtifact(
                            artifact_type="Prefetch",
                            source_path=f"/Windows/Prefetch/{name}",
                            extracted_to=out_path,
                        )
                    )
                except Exception as e:
                    logger.warning(f"Failed to extract file {name}: {e}")
    except Exception as e:
        logger.warning(f"Could not open /Windows/Prefetch directory: {e}")
    return artifacts


def _parse_shimcache(fs: Any) -> Optional[DigitalArtifact]:
    """Helper to parse ShimCache from SYSTEM hive."""
    if not REGISTRY_AVAILABLE or not Registry:
        logger.warning("python-registry not installed. Skipping ShimCache.")
        return None

    if not PYTSK_AVAILABLE:
        logger.warning("pytsk3 not available, skipping ShimCache.")
        return None

    try:
        system_hive_file = fs.open("/Windows/System32/config/SYSTEM")
        hive_data = system_hive_file.read_random(0, system_hive_file.info.meta.size)

        import io

        hive_io = io.BytesIO(hive_data)
        reg = Registry.Registry(hive_io)

        key_path = r"ControlSet001\\Control\\Session Manager\\AppCompatCache"
        shim_key = reg.open(key_path)
        shim_value = shim_key.value("AppCompatCache").value()

        details = {
            "key_path": key_path,
            "value_name": "AppCompatCache",
            "data_size": len(shim_value),
            "note": "Binary ShimCache blob read successfully. Full decode requires parser.",
        }

        return DigitalArtifact(
            artifact_type="ShimCache",
            source_path="/Windows/System32/config/SYSTEM",
            details=details,
        )
    except Exception as e:
        logger.warning(f"Failed to parse ShimCache: {e}")
        return None


def extract_disk_artifacts(image_path: str, output_dir: str) -> ArtifactExtractionResult:
    """Forensic utility to extract digital artifacts from disk images."""
    logger.info(f"Starting artifact extraction from: {image_path}")

    if not PYTSK_AVAILABLE or not pytsk3:
        return ArtifactExtractionResult(image_path=image_path, error="pytsk3 library not found.")
    if not os.path.exists(image_path):
        return ArtifactExtractionResult(image_path=image_path, error="Disk image not found.")

    os.makedirs(output_dir, exist_ok=True)

    artifacts: List[DigitalArtifact] = []

    try:
        img = pytsk3.Img_Info(image_path)
        fs = pytsk3.FS_Info(img)

        logger.info("Extracting Prefetch files...")
        artifacts.extend(_extract_prefetch_files(fs, output_dir))

        logger.info("Parsing ShimCache...")
        shim = _parse_shimcache(fs)
        if shim:
            artifacts.append(shim)

    except Exception as e:
        logger.error(f"Failed to open or analyze disk image: {e}")
        return ArtifactExtractionResult(image_path=image_path, error=str(e))

    return ArtifactExtractionResult(
        image_path=image_path,
        artifacts_found=artifacts,
        total_extracted=len(artifacts),
    )


# --- Typer CLI ---


internal_app = typer.Typer()


@internal_app.command("analyze-log")
def run_log_analysis(
    file_path: str = typer.Argument(..., help="Path to the log file to analyze."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON."),
):
    results = analyze_log_file(file_path)
    if results.error:
        typer.echo(f"Error: {results.error}", err=True)
        sys.exit(1)
    save_or_print_results(results.model_dump(), output_file)


@internal_app.command("static-analysis")
def run_static_analysis(
    file_path: str = typer.Argument(..., help="Path to the file for static analysis."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON."),
):
    results = perform_static_analysis(file_path)
    if results.error:
        typer.echo(f"Error: {results.error}", err=True)
        sys.exit(1)
    save_or_print_results(results.model_dump(), output_file)


@internal_app.command("parse-mft")
def run_mft_parsing(
    file_path: str = typer.Argument(..., help="Path to the $MFT file to parse."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON."),
):
    results = parse_mft(file_path)
    if results.error:
        typer.echo(f"Error: {results.error}", err=True)
        sys.exit(1)
    save_or_print_results(results.model_dump(), output_file)


@internal_app.command("extract-artifacts")
def run_artifact_extraction(
    image_path: str = typer.Argument(..., help="Path to disk image (e.g. .E01, .dd, .vhd)."),
    extract_dir: str = typer.Option("./artifacts", "--extract-dir", help="Directory to save artifacts."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON."),
):
    results = extract_disk_artifacts(image_path, extract_dir)
    if results.error:
        typer.echo(f"Error: {results.error}", err=True)
        sys.exit(1)
    save_or_print_results(results.model_dump(), output_file)
