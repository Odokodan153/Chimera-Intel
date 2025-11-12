"""
Creative Asset Workflow Module.

Handles the processing of master templates (e.g., PSD) into derivative
assets with signed, auditable provenance manifests.

This module implements the workflow for Req 8 (Photoshop + CI templates):
1.  Loads a master PSD file using 'psd-tools'.
2.  Reads base metadata from a 'PROVENANCE_MANIFEST' text layer.
3.  Composites and exports a derivative (PNG/JPG) using PIL.
4.  Calculates the SHA256 hash of the derivative.
5.  Creates a 'CreativeAssetManifest' (JSON) with the specified fields.
6.  Signs the manifest with a private key.
7.  Gets an RFC3161 timestamp for the manifest.
8.  Wraps all proofs into a 'SignedCreativeEnvelope'.
9.  Stores both the derivative and the signed envelope in the database
    using the 'local_db_service'.
"""

import typer
import json
import pathlib
import logging
import hashlib
import base64
import io
import uuid # Added for generating unique asset IDs
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from pydantic import BaseModel, Field

# --- Core Dependencies ---
try:
    from PIL import Image
except ImportError:
    Image = None

try:
    from psd_tools import PSDImage
except ImportError:
    PSDImage = None # type: ignore

# --- Cryptographic Imports (reused from other modules) ---
try:
    import rfc3161
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    # Import reusable helpers from forensic_vault and provenance_service
    from chimera_intel.core.forensic_vault import (
        _load_private_key, 
        _get_timestamp_token
    )
    from chimera_intel.core.provenance_service import _canonical_json_bytes
    
except ImportError:
    # Handle missing crypto dependencies
    rfc3161 = None
    hashes = None
    padding = None
    _load_private_key = None # type: ignore
    _get_timestamp_token = None # type: ignore
    _canonical_json_bytes = None # type: ignore

# --- Project Imports ---
from chimera_intel.core.schemas import BaseResult
from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.config_loader import CONFIG
# --- MODIFICATION: Import real storage function ---
from chimera_intel.core.local_db_service import save_scan_to_db
# --- END MODIFICATION ---

# --- Setup ---
logger = logging.getLogger(__name__)
creative_app = typer.Typer(
    name="creative-workflow",
    help="Manage master templates and export signed derivatives.",
)

# --- Schemas (as requested) ---

class CreativeAssetManifest(BaseModel):
    """
    The core JSON manifest describing a derivative asset, based on
    the CI template standard (Req 8).
    """
    file_name: str = Field(..., description="The filename of the derivative asset.")
    sha256: str = Field(..., description="SHA-256 hash of the derivative asset's bytes.")
    editor_id: str = Field(..., description="The ID of the operator who exported the asset.")
    timestamp: str = Field(..., description="ISO 8601 timestamp of the export.")
    origin_assets: List[str] = Field(default_factory=list, description="List of vault IDs for source/origin assets (e.g., master PSD).")
    model_info: List[str] = Field(default_factory=list, description="List of models used (e.g., 'photoshop:v24.0', 'stable-diffusion:v1.5').")
    consent_ids: List[str] = Field(default_factory=list, description="List of consent_artifact_id's linked to this asset.")
    watermark_id: Optional[str] = Field(None, description="Identifier for any embedded watermarks (e.g., LSB JWT).")
    c2pa_token: Optional[str] = Field(None, description="A C2PA manifest token, if generated.")

class SignedCreativeEnvelope(BaseModel):
    """
    The final signed artifact that is stored in the vault.
    It wraps the manifest and its cryptographic proofs.
    (Reuses pattern from provenance_service.py)
    """
    manifest: CreativeAssetManifest
    signature: str = Field(..., description="Base64-encoded signature of the canonicalized manifest JSON.")
    tsa_token_b64: Optional[str] = Field(None, description="Base64-encoded RFC3161 timestamp token for the manifest.")

class ExportResult(BaseResult):
    """The result of a successful export operation."""
    derivative_asset_id: str
    manifest_asset_id: str
    derivative_logical_path: str
    manifest_logical_path: str
    signed_envelope: SignedCreativeEnvelope

# --- Core Service Functions ---

def _check_dependencies():
    """Check for all required libraries."""
    if not all([Image, PSDImage, rfc3161, _load_private_key, _canonical_json_bytes, save_scan_to_db]):
        logger.critical("Missing dependencies. Please run: pip install pillow psd-tools cryptography rfc3161-client")
        logger.critical("Also ensure 'local_db_service' is available.")
        raise typer.Exit(code=1)

def _read_psd_manifest_layer(psd: Any) -> Dict[str, Any]:
    """Finds and parses the 'PROVENANCE_MANIFEST' text layer."""
    try:
        for layer in psd:
            if layer.is_group():
                continue # Simple recursive search disabled for clarity
            if layer.name.upper() == "PROVENANCE_MANIFEST" and layer.kind == "type":
                logger.info("Found 'PROVENANCE_MANIFEST' layer.")
                layer_text = getattr(layer, 'text', '')
                if layer_text:
                    # Replace smart quotes/typography that can break JSON parsing
                    clean_text = layer_text.replace(u"\u201d", '"').replace(u"\u201c", '"')
                    return json.loads(clean_text)
        logger.warning("No 'PROVENANCE_MANIFEST' text layer found in PSD.")
        return {}
    except Exception as e:
        logger.error(f"Failed to parse 'PROVENANCE_MANIFEST' layer: {e}")
        return {}

def _calculate_sha256_bytes(data: bytes) -> str:
    """Calculates the SHA256 hash of a byte string."""
    return hashlib.sha256(data).hexdigest()

def export_and_sign_derivative(
    psd_path: pathlib.Path,
    editor_id: str,
    key_path: pathlib.Path,
    output_format: str = "png",
    consent_ids: Optional[List[str]] = None,
    tsa_url: Optional[str] = None
) -> ExportResult:
    """
    Full pipeline: Loads PSD, exports derivative, creates signed manifest,
    and stores both in the database via local_db_service.
    """
    _check_dependencies()
    
    if output_format.lower() not in ["png", "jpg"]:
        raise ValueError("Output format must be 'png' or 'jpg'.")
        
    logger.info(f"Loading master PSD: {psd_path.name}")
    psd = PSDImage.open(psd_path)
    
    # 1. Read base metadata from PSD layer
    base_manifest = _read_psd_manifest_layer(psd)
    
    # 2. Composite PSD and export to bytes
    logger.info("Compositing master image...")
    pil_image = psd.composite()
    
    img_byte_arr = io.BytesIO()
    if output_format.lower() == "jpg":
        if pil_image.mode != "RGB":
            pil_image = pil_image.convert("RGB")
        pil_image.save(img_byte_arr, "JPEG", quality=95)
        derivative_filename = psd_path.with_suffix(".jpg").name
    else:
        pil_image.save(img_byte_arr, "PNG")
        derivative_filename = psd_path.with_suffix(".png").name
        
    derivative_bytes = img_byte_arr.getvalue()
    logger.info(f"Exported {derivative_filename} ({len(derivative_bytes)} bytes)")

    # 3. Calculate hash of derivative
    derivative_hash = _calculate_sha256_bytes(derivative_bytes)
    
    # 4. Create the manifest
    logger.info("Creating creative asset manifest...")
    manifest = CreativeAssetManifest(
        file_name=derivative_filename,
        sha256=derivative_hash,
        editor_id=editor_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        origin_assets=base_manifest.get("origin_assets", [f"master:{psd_path.name}"]),
        model_info=base_manifest.get("model_info", ["photoshop:unknown"]),
        consent_ids=consent_ids or base_manifest.get("consent_ids", []),
        watermark_id=base_manifest.get("watermark_id"),
        c2pa_token=base_manifest.get("c2pa_token")
    )
    
    # 5. Sign and Timestamp the manifest (reusing logic from provenance_service)
    logger.info("Signing and timestamping manifest...")
    private_key = _load_private_key(key_path)
    manifest_bytes = _canonical_json_bytes(manifest)
    
    signature = private_key.sign(
        manifest_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    sig_b64 = base64.b64encode(signature).decode("utf-8")

    tsa_token_b64 = None
    if tsa_url:
        ts_token_bytes, _ = _get_timestamp_token(manifest_bytes, tsa_url)
        if ts_token_bytes:
            tsa_token_b64 = base64.b64encode(ts_token_bytes).decode("utf-8")
        else:
            logger.warning("Failed to retrieve timestamp, proceeding without it.")

    # 6. Create the final envelope
    signed_envelope = SignedCreativeEnvelope(
        manifest=manifest,
        signature=sig_b64,
        tsa_token_b64=tsa_token_b64
    )
    
    # 7. Store artifacts in the database (using local_db_service)
    logger.info("Storing artifacts in database...")
    
    # --- Store the derivative image ---
    # We store the blob as b64, similar to evidence_vault.py
    asset_id = f"deriv-{uuid.uuid4()}"
    derivative_b64 = base64.b64encode(derivative_bytes).decode('latin-1')
    derivative_logical_path = f"creative_assets/derivatives/{derivative_filename}"
    
    save_scan_to_db(
        target=psd_path.name,
        module="creative_derivative",
        data={
            "file_name": derivative_filename,
            "logical_path": derivative_logical_path,
            "format": output_format,
            "editor_id": editor_id,
            "b64_content": derivative_b64
        },
        scan_id=asset_id
    )
    
    # --- Store the signed manifest JSON ---
    manifest_id = f"manifest-{asset_id}"
    manifest_logical_path = f"creative_assets/manifests/{derivative_filename}.manifest.json"
    
    save_scan_to_db(
        target=psd_path.name,
        module="creative_manifest",
        data={
            "file_name": derivative_filename + ".manifest.json",
            "logical_path": manifest_logical_path,
            "derivative_asset_id": asset_id,
            "envelope": signed_envelope.model_dump(by_alias=True)
        },
        scan_id=manifest_id
    )
    
    logger.info("Export and signing complete.")
    return ExportResult(
        derivative_asset_id=asset_id,
        manifest_asset_id=manifest_id,
        derivative_logical_path=derivative_logical_path,
        manifest_logical_path=manifest_logical_path,
        signed_envelope=signed_envelope
    )

# --- CLI ---

@creative_app.command("export-psd", help="Export a derivative from a PSD and create a signed manifest.")
def cli_export_psd(
    psd_path: pathlib.Path = typer.Argument(..., exists=True, help="Path to the master .psd file."),
    key_path: pathlib.Path = typer.Option(..., "--key", "-k", exists=True, help="Path to the private key (.pem) for signing."),
    editor_id: str = typer.Option(..., "--editor", help="The ID of the editor/operator."),
    output_format: str = typer.Option("png", "--format", help="Output format: 'png' or 'jpg'."),
    consent_id: Optional[List[str]] = typer.Option(None, "--consent-id", help="Link a consent_id (can be used multiple times)."),
    tsa_url: Optional[str] = typer.Option(CONFIG.get("tsa_url", "http://timestamp.digicert.com"), "--tsa-url", help="RFC3161 Timestamping Authority URL."),
    output_file: Optional[pathlib.Path] = typer.Option(None, "--output", "-o", help="Save final export result to a JSON file."),
):
    """
    CLI for the full creative asset export pipeline.
    """
    with console.status("[bold cyan]Exporting and signing creative asset...[/bold cyan]"):
        try:
            # --- MODIFICATION: Removed mock vault instantiation ---
            # The vault is no longer needed as an argument
            
            result = export_and_sign_derivative(
                psd_path=psd_path,
                editor_id=editor_id,
                key_path=key_path,
                output_format=output_format,
                consent_ids=consent_id,
                tsa_url=tsa_url
            )
            # --- END MODIFICATION ---
            
            console.print("\n[bold green]Creative Asset Export Successful[/bold green]")
            console.print(f"  - Derivative Asset ID: {result.derivative_asset_id}")
            console.print(f"  - Manifest Asset ID:   {result.manifest_asset_id}")
            console.print(f"  - Asset SHA256:        {result.signed_envelope.manifest.sha256}")
            
            if output_file:
                save_or_print_results(result.model_dump(exclude_none=True, by_alias=True), output_file)

        except Exception as e:
            console.print(f"\n[bold red]Error during export:[/bold red] {e}")
            logger.exception("Creative workflow export failed")
            raise typer.Exit(code=1)

if __name__ == "__main__":
    creative_app()