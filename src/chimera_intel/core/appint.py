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
from typing import Optional, List, Dict, Any 
from .schemas import StaticAppAnalysisResult, FoundSecret, DeepMetadata, DeviceIntelResult
from .utils import save_or_print_results, console
from .database import save_scan_to_db
try:
    import ezdxf
    EZDXF_AVAILABLE = True
except ImportError:
    ezdxf = None
    EZDXF_AVAILABLE = False

try:
    import shapefile
    PYSHP_AVAILABLE = True
except ImportError:
    shapefile = None
    PYSHP_AVAILABLE = False
    
try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    olefile = None
    OLEFILE_AVAILABLE = False

try:
    import exifread
    EXIFREAD_AVAILABLE = True
except ImportError:
    exifread = None
    EXIFREAD_AVAILABLE = False

logger = logging.getLogger(__name__)


def analyze_apk_static(file_path: str) -> StaticAppAnalysisResult:
    """
    Performs static analysis on an APK file by decompiling it and searching for secrets.

    NOTE: This function requires 'apktool' to be installed and in the system's PATH.

    Args:
        file_path (str): The path to the .apk file to analyze.

    Returns:
        StaticAppAnalysisResult: A Pantic model with the analysis results.
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


# --- ADDED: Real Deep Metadata Parser ---

def parse_deep_metadata(file_path: str) -> DeepMetadata:
    """
    Extracts and correlates non-standard metadata from niche file types
    using specialized libraries.
    """
    logger.info(f"Parsing deep metadata from: {file_path}")

    if not os.path.exists(file_path):
        return DeepMetadata(file_path=file_path, file_type="Unknown", error="File not found.")

    file_type = "Unknown"
    metadata: Dict[str, Any] = {}
    error: Optional[str] = None

    try:
        lower_path = file_path.lower()
        
        # 1. CAD Files (.dwg, .dxf)
        if (lower_path.endswith(".dwg") or lower_path.endswith(".dxf")):
            if not EZDXF_AVAILABLE or not ezdxf:
                error = "ezdxf library not found. Cannot parse CAD files."
            else:
                file_type = "AutoCAD Drawing"
                doc = ezdxf.readfile(file_path)
                metadata = {
                    "dxf_version": doc.dxfversion,
                    "author": doc.header.get('$AUTHOR', 'N/A'),
                    "last_saved_by": doc.header.get('$LASTSAVEDBY', 'N/A'),
                    "total_entities": len(doc.modelspace()),
                    "layers": [layer.dxf.name for layer in doc.layers],
                }

        # 2. GIS Shapefiles (.shp)
        elif lower_path.endswith(".shp"):
            if not PYSHP_AVAILABLE or not shapefile:
                error = "pyshp library not found. Cannot parse Shapefiles."
            else:
                file_type = "GIS Shapefile"
                with shapefile.Reader(file_path) as shp:
                    metadata = {
                        "shape_type": shp.shapeTypeName,
                        "num_records": shp.numRecords,
                        "bbox": shp.bbox,
                        "fields": [f[0] for f in shp.fields[1:]]
                    }

        # 3. OLE Documents (.doc, .xls, .ppt, .docm, .xlsm)
        elif any(lower_path.endswith(ext) for ext in ['.doc', '.xls', '.ppt', '.docm', '.xlsm']):
            if not OLEFILE_AVAILABLE or not olefile:
                error = "olefile library not found. Cannot parse OLE documents."
            elif olefile.isOleFile(file_path):
                file_type = "OLE Document"
                with olefile.OleFileIO(file_path) as ole:
                    meta = ole.get_meta()
                    metadata = {
                        "streams": ole.listdir(),
                        "has_macros": ole.exists('Macros') or ole.exists('_VBA_PROJECT_CUR'),
                        "author": getattr(meta, 'author', b'N/A').decode('utf-8', 'ignore'),
                        "title": getattr(meta, 'title', b'N/A').decode('utf-8', 'ignore'),
                        "last_saved_by": getattr(meta, 'last_saved_by', b'N/A').decode('utf-8', 'ignore'),
                    }
            else:
                file_type = "Modern Office Document (XML)"
                error = "File is a modern Office XML format (e.g., .docx), not an OLE file. Parsing requires different libraries (e.g., python-docx)."

        # 4. Image EXIF Data
        elif any(lower_path.endswith(ext) for ext in ['.jpg', '.jpeg', '.tif', '.tiff']):
            if not EXIFREAD_AVAILABLE or not exifread:
                error = "exifread library not found. Cannot parse EXIF data."
            else:
                file_type = "Image (EXIF)"
                with open(file_path, 'rb') as f:
                    tags = exifread.process_file(f, details=False)
                    metadata = {tag: str(value) for tag, value in tags.items() if tag not in ['JPEGThumbnail']}

        else:
            file_type = "Standard File"
            metadata = {"info": "File type does not have a specialized metadata parser."}
            
        return DeepMetadata(
            file_path=file_path,
            file_type=file_type,
            metadata=metadata,
            error=error
        )
        
    except Exception as e:
        logger.error(f"Failed during deep metadata parsing for {file_path}: {e}")
        return DeepMetadata(file_path=file_path, file_type=file_type, error=str(e))


# --- REWRITTEN: Device Intelligence Function ---

def get_device_intel() -> DeviceIntelResult:
    """
    Connects to an Android device via ADB to pull device metadata and app lists.
    
    NOTE: Requires 'adb' to be installed and a device to be connected.
    """
    console.print("[cyan]Querying connected device via ADB...[/cyan]")
    props = {}
    
    def run_adb_command(command: List[str]) -> List[str]:
        """Helper to run an ADB command and return its output lines."""
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return [line.replace("package:", "") for line in result.stdout.splitlines() if line]

    try:
        # 1. Get Device Properties
        console.print("Fetching device properties...")
        result_props = subprocess.run(
            ["adb", "shell", "getprop"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        for line in result_props.stdout.splitlines():
            match = re.match(r'\[(.*?)\]: \[(.*?)\]', line)
            if match:
                key, value = match.groups()
                if key.startswith("ro.product") or key in ["ro.build.version.sdk", "ro.serialno"]:
                    props[key] = value

        # 2. (REAL) Get Third-Party (user) Installed Packages
        console.print("Fetching third-party packages...")
        third_party_packages = run_adb_command(["adb", "shell", "pm", "list", "packages", "-3"])
        
        # 3. (REAL) Get System ("hidden") Packages
        console.print("Fetching system packages...")
        system_packages = run_adb_command(["adb", "shell", "pm", "list", "packages", "-s"])

        # Combine them for the "all packages" list
        all_packages = list(set(third_party_packages + system_packages))

        return DeviceIntelResult(
            device_properties=props,
            installed_packages=all_packages, # Full list
            hidden_packages=system_packages # System/ROM-installed (replaces mock)
        )
        
    except FileNotFoundError:
        return DeviceIntelResult(error="adb command not found. Please install the Android SDK Platform-Tools.")
    except subprocess.CalledProcessError as e:
        if "no devices" in e.stderr:
            return DeviceIntelResult(error="No ADB device found. Is it connected and authorized?")
        return DeviceIntelResult(error=f"ADB command failed: {e.stderr}")
    except subprocess.TimeoutExpired:
        return DeviceIntelResult(error="ADB command timed out. Is the device responsive?")
    except Exception as e:
        return DeviceIntelResult(error=f"An unexpected error occurred: {e}")

# --- END REWRITE ---

appint_app = typer.Typer()


@appint_app.command("static")
def run_static_apk_analysis(
    # --- FIX REVERTED: Use standard typer.Argument syntax ---
    file_path: str = typer.Argument(..., help="Path to the .apk file to analyze."),
    # --------------------------------------------------
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
    # --- FIX APPLIED ---
    # Catch typer.Exit and re-raise it immediately so it's not
    # caught by the generic 'except Exception' block.
    except typer.Exit:
        raise
    # --- END FIX ---
    except Exception as e:
        console.print(f"[red]An unexpected error occurred: {e}[/red]")
        raise typer.Exit(code=1)


@appint_app.command("deep-metadata") # <-- ADDED
def run_deep_metadata_parser(
    file_path: str = typer.Argument(..., help="Path to the file to analyze (e.g., .dwg, .shp, .doc, .jpg)."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Extracts non-standard metadata from niche file types.
    """
    try:
        results_model = parse_deep_metadata(file_path)
        if results_model.error and not results_model.metadata: # Only fail if there's an error AND no metadata
            console.print(f"[red]Deep metadata parsing failed: {results_model.error}[/red]")
            raise typer.Exit(code=1)

        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]An unexpected error occurred: {e}[/red]")
        raise typer.Exit(code=1)


# --- ADDED: New command for Device Intel ---
@appint_app.command("device-intel")
def run_device_intel(
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Scans a connected device via ADB for metadata and 'hidden' apps.
    """
    try:
        results_model = get_device_intel()
        if results_model.error:
            console.print(f"[red]Device intel failed: {results_model.error}[/red]")
            raise typer.Exit(code=1)

        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        
        target = results_dict.get("device_properties", {}).get("ro.serialno", "unknown_device")
        save_scan_to_db(
            target=target,
            module="appint_device_intel",
            data=results_dict,
        )
        
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]An unexpected error occurred: {e}[/red]")
        raise typer.Exit(code=1)