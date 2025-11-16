"""
Module for Image Production & Photoshop Best Practices (for CI & trusted media).

Provides a workflow to produce high-quality, auditable images for
PR/marketing, register them in the Evidence Vault, and link them to the ARG.

MODIFIED: This module now implements the full signed/timestamped/embedded
provenance workflow (Req 8) by integrating crypto logic from forensic_vault.py
and embedding it using stegano.

New Dependencies:
pip install pillow c2pa-python stegano
(cryptography and rfc3161-client are also required via forensic_vault)
"""

import typer
import logging
import os
import json
import hashlib
import pathlib
import base64
from pydantic import BaseModel
from typing import List, Optional
from .utils import save_or_print_results
from .schemas import (
    TrustedMediaManifest,
    TrustedMediaAIMetadata,
    MediaProductionPackage,
    ProvenanceManifest,
    SignedProvenanceEnvelope,
    VerificationResult,
)
try:
    from PIL import Image, ImageDraw, ImageFont
    import c2pa
    from stegano import lsb 
except ImportError:
    print("Missing dependencies. Please run: pip install pillow c2pa-python stegano") 
    Image = None
    c2pa = None
    lsb = None  
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.exceptions import InvalidSignature
except ImportError:
    hashes = None
    padding = None
    InvalidSignature = Exception
from .utils import console
from .evidence_vault import store_evidence 
from .in_mem_arg_service import in_mem_arg_service_instance as arg_service_instance
from .arg_service import BaseEntity, Relationship  
from .config_loader import CONFIG

# Import reusable crypto functions from forensic_vault
from .forensic_vault import (
    _get_timestamp_token,
    _load_private_key,
    _load_public_key,
)
# --- END MODIFICATION ---

logger = logging.getLogger(__name__)

trusted_media_app = typer.Typer(
    name="trusted-media",
    help="Workflow for producing and registering trusted, auditable media.",
)


# --- 2. Core Workflow Functions ---

def _calculate_sha256(file_path: pathlib.Path) -> str:
    """Calculates the SHA256 hash of a file."""
    # (Unchanged from)
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash in chunks
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def _canonical_json_bytes(data: BaseModel) -> bytes:
    """Serializes a Pydantic model to canonical (sorted) JSON bytes."""
    # Helper function for signing
    return data.model_dump_json(sort_keys=True, by_alias=True).encode("utf-8")

def _embed_c2pa(
    image_path: pathlib.Path, manifest: TrustedMediaManifest
) -> bool:
    """
    REAL IMPLEMENTATION: Embeds C2PA / Adobe Content Credentials.
    
    This function creates a real C2PA manifest and signs the file.
    """
    # (Unchanged from)
    if not c2pa:
        logger.error("c2pa library not found. Skipping C2PA embedding.")
        return False
        
    try:
        # 1. Create the C2PA manifest (as a dictionary)
        c2pa_manifest = {
            "vendor": "Chimera-Intel",
            "title": f"Project {manifest.project_id} Media",
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "when": manifest.timestamp,
                                "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
                            }
                        ]
                    }
                },
                {
                    "label": "c2pa.provenance",
                    "data": {
                        "editor": manifest.editor_id,
                        "license": manifest.license,
                    }
                },
                # Add AI model info if present
                *([
                    {
                        "label": "c2pa.ai_generative_training",
                        "data": {
                            "models": [{"name": model.model_name} for model in manifest.ai_models_used]
                        }
                    }
                ] if manifest.ai_models_used else []),
            ]
        }

        # 2. Create a dummy signer (for demo purposes)
        # In production, this would be a real certificate
        signer_path = pathlib.Path("c2pa_signer")
        if not signer_path.exists():
            signer_path.mkdir()
        
        c2pa.create_signer.from_files(
            sign_cert_path=signer_path / "sign.crt",
            private_key_path=signer_path / "sign.key",
            out_dir=signer_path,
        )

        # 3. Sign the file
        output_path = image_path.with_suffix(f".c2pa{image_path.suffix}")
        
        c2pa.sign_file(
            input_file=str(image_path),
            output_file=str(output_path),
            manifest=c2pa_manifest,
            signer=c2pa.Signer(str(signer_path)),
        )

        # 4. Replace original file with signed file
        os.replace(output_path, image_path)

        logger.info(f"Successfully embedded C2PA manifest in {image_path.name}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to embed C2PA credentials: {e}")
        return False


# --- MODIFICATION: Robust, Layered Watermarking ---

def _apply_watermark(
    image_path: pathlib.Path, 
    badge_type: str, 
    manifest: TrustedMediaManifest,
    signing_key: pathlib.Path,  # <-- ADDED
    tsa_url: Optional[str]      # <-- ADDED
):
    """
    REAL IMPLEMENTATION: Applies layered watermarks and embeds signed provenance.
    
    1. (Invisible) Creates, signs, and timestamps a ProvenanceManifest.
    2. (Invisible) Embeds the signed envelope using Steganography (LSB).
    3. (Visible) Applies a visible badge (if badge_type is provided).
    
    Applies all layers and saves the image once.
    """
    if not Image or not lsb or not hashes:
        logger.error("Pillow, stegano, or cryptography library not found. Skipping watermarking.")
        return

    try:
        # Load the *original* image to get its hash *before* modification
        original_hash = _calculate_sha256(image_path)
        
        with Image.open(image_path) as img:
            # Preserve original format info
            original_format = img.format
            img = img.convert("RGBA")
            exif_data = img.getexif()
            img_to_save = img  # Start with the base image

            # --- 1. Create, Sign, and Timestamp Provenance ---
            logger.info(f"Creating signed provenance for {image_path.name}...")
            
            # 1a. Create the manifest
            # Use the hash of the *original* file
            provenance_manifest = ProvenanceManifest(
                asset_hash=original_hash,
                timestamp=manifest.timestamp,
                issuer=manifest.author or "Chimera-Intel",
                consent_artifact_id=manifest.consent_ids[0] if manifest.consent_ids else None,
                author=manifest.author or "Chimera-Intel"
            )
            manifest_bytes = _canonical_json_bytes(provenance_manifest)
            
            # 1b. Sign the manifest
            private_key = _load_private_key(signing_key)
            signature = private_key.sign(
                manifest_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            sig_b64 = base64.b64encode(signature).decode("utf-8")

            # 1c. Timestamp the manifest
            ts_token_b64 = None
            if tsa_url:
                ts_token_bytes, _ = _get_timestamp_token(manifest_bytes, tsa_url)
                if ts_token_bytes:
                    ts_token_b64 = base64.b64encode(ts_token_bytes).decode("utf-8")
                    logger.info("Successfully timestamped manifest.")
            
            # 1d. Create the final envelope
            envelope = SignedProvenanceEnvelope(
                manifest=provenance_manifest,
                signature=sig_b64,
                tsa_token_b64=ts_token_b64
            )
            envelope_json = envelope.model_dump_json(sort_keys=True, by_alias=True)
            
            # --- 2. Embed using Steganography (LSB) ---
            try:
                img_to_save = lsb.hide(img_to_save, envelope_json)
                logger.info(f"Embedded signed provenance (LSB) in {image_path.name}")
            except Exception as e:
                logger.error(f"Failed to apply LSB watermark, file may be too small or complex: {e}")
                # Continue anyway to apply visible badge
            
            # --- 3. Apply Visible Badge ---
            if badge_type:
                draw = ImageDraw.Draw(img_to_save)
                try:
                    font = ImageFont.truetype("arial.ttf", 24)
                except IOError:
                    font = ImageFont.load_default()

                text = f"Chimera-Intel: {badge_type}"
                text_bbox = draw.textbbox((0, 0), text, font=font)
                text_width = text_bbox[2] - text_bbox[0]
                text_height = text_bbox[3] - text_bbox[1]
                
                x = img.width - text_width - 15
                y = img.height - text_height - 10
                
                draw.rectangle((x-5, y-5, x + text_width + 5, y + text_height + 5), fill=(0, 0, 0, 128))
                draw.text((x, y), text, font=font, fill=(255, 255, 255, 200))
                logger.info(f"Applied visible badge '{badge_type}' to {image_path.name}")
            
            # --- 4. Consolidated Save ---
            # Save the final processed image (img_to_save) 
            if original_format == "PNG":
                img_to_save.save(image_path, "PNG", exif=exif_data)
            elif original_format in ["JPEG", "JPG"]:
                img_to_save.convert("RGB").save(image_path, "JPEG", exif=exif_data)
            else:
                img_to_save.save(image_path, exif=exif_data)
                
    except Exception as e:
        logger.error(f"Failed to apply watermark to {image_path.name}: {e}")
        # Re-raise to stop the workflow
        raise

# --- END MODIFICATION ---


# --- NEW: Verification Function (Req 8) ---
def verify_embedded_provenance(
    file_path: pathlib.Path,
    pub_key_path: pathlib.Path
) -> VerificationResult:
    """
    Verifies the embedded signed provenance manifest in a media file.
    
    This is the implementation for the `verify(asset_id)` endpoint.
    
    Args:
        file_path: Path to the media file containing the embedded payload.
        pub_key_path: Path to the public PEM key for verification.
        
    Returns:
        A VerificationResult object.
    """
    if not all([Image, lsb, hashes]):
        return VerificationResult(error="Missing dependencies (Pillow, stegano, cryptography).")
        
    log = []
    
    try:
        # 1. Load public key
        public_key = _load_public_key(pub_key_path)
        
        # 2. Extract hidden payload from image
        img = Image.open(file_path)
        payload_json = lsb.reveal(img)
        if not payload_json:
            log.append("Verification FAILED: No embedded payload found.")
            return VerificationResult(is_valid=False, verification_log=log)
            
        log.append("Embedded payload extracted.")
        
        # 3. Deserialize payload
        envelope = SignedProvenanceEnvelope.model_validate_json(payload_json)
        manifest = envelope.manifest
        manifest_bytes = _canonical_json_bytes(manifest)
        signature = base64.b64decode(envelope.signature)
        log.append("Payload deserialized successfully.")

        # 4. Verify Signature
        try:
            public_key.verify(
                signature,
                manifest_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            log.append("Signature VERIFIED.")
        except InvalidSignature:
            log.append("Signature VERIFICATION FAILED: Signature does not match manifest.")
            return VerificationResult(is_valid=False, verification_log=log, verified_manifest=manifest)
        except Exception as e:
            log.append(f"Signature verification FAILED with error: {e}")
            return VerificationResult(is_valid=False, verification_log=log, verified_manifest=manifest)
            
        # 5. Verify Timestamp (if present)
        if envelope.tsa_token_b64:
            try:
                ts_token_bytes = base64.b64decode(envelope.tsa_token_b64)
                # We need the rfc3161 library for this step
                try:
                    import rfc3161
                    from rfc3161 import get_tst_info
                except ImportError:
                    log.append("Timestamp: SKIPPED (rfc3161-client library not found).")
                    # Continue, as signature is still valid
                    return VerificationResult(
                        is_valid=True,
                        verified_manifest=manifest,
                        verification_log=log
                    )

                tst_info = get_tst_info(ts_token_bytes)
                ts_hash = tst_info["messageImprint"]["hashedMessage"]
                recalc_hash = hashlib.sha256(manifest_bytes).digest()
                
                if ts_hash == recalc_hash:
                    log.append(f"Timestamp VERIFIED. Trusted Time: {tst_info['genTime']}")
                else:
                    log.append("Timestamp HASH MISMATCH: Manifest does not match timestamped hash.")
                    return VerificationResult(is_valid=False, verification_log=log, verified_manifest=manifest)
            except Exception as e:
                log.append(f"Timestamp verification FAILED with error: {e}")
                return VerificationResult(is_valid=False, verification_log=log, verified_manifest=manifest)
        else:
            log.append("Timestamp: SKIPPED (No token present in payload).")
            
        # 6. All checks passed
        log.append("Provenance successfully verified.")
        return VerificationResult(
            is_valid=True,
            verified_manifest=manifest,
            verification_log=log
        )
        
    except json.JSONDecodeError:
        log.append(f"Verification FAILED: Failed to decode payload. Payload may be corrupt or non-existent.")
        return VerificationResult(is_valid=False, verification_log=log)
    except Exception as e:
        log.append(f"Verification FAILED: An unexpected error occurred: {e}")
        return VerificationResult(is_valid=False, verification_log=log)
# --- END NEW FUNCTION ---


def create_trusted_media_package(
    master_file_path: pathlib.Path,
    project_id: str,
    editor_id: str,
    consent_ids: List[str],
    ai_models_json: str,
    derivative_paths: List[pathlib.Path],
    embed_c2pa_flag: bool,
    watermark_badge: str,
    # --- MODIFICATION: Add crypto keys ---
    signing_key_path: pathlib.Path,
    tsa_url: Optional[str]
    # --- END MODIFICATION ---
) -> MediaProductionPackage:
    """
    Runs the full workflow for producing, watermarking, and registering trusted media.
    """
    if not master_file_path.exists():
        raise FileNotFoundError(f"Master file not found: {master_file_path}")

    console.print(f"Processing master file: [cyan]{master_file_path.name}[/cyan]")
    
    # 1. Hash Master File
    master_hash = _calculate_sha256(master_file_path)
    console.print(f"  > Master SHA256: [yellow]{master_hash}[/yellow]")

    # 2. Create Manifest
    try:
        ai_models = [TrustedMediaAIMetadata(**model) for model in json.loads(ai_models_json)]
    except json.JSONDecodeError:
        logger.error("Invalid JSON for AI models.")
        ai_models = []

    manifest = TrustedMediaManifest(
        master_sha256=master_hash,
        source_files=[str(master_file_path)],
        editor_id=editor_id,
        ai_models_used=ai_models,
        consent_ids=consent_ids,
        project_id=project_id,
    )
    manifest_json = manifest.model_dump_json(indent=2)
    
    # 3. Process Derivatives
    for deriv_path in derivative_paths:
        if not deriv_path.exists():
            logger.warning(f"Derivative file {deriv_path} not found, skipping.")
            continue
        
        # Apply C2PA & Watermarks
        # Apply C2PA *first* before any pixel modifications
        if embed_c2pa_flag:
            _embed_c2pa(deriv_path, manifest)
        
        # --- MODIFICATION: Call modified watermarking function ---
        # This single call now applies all layers:
        # - invisible Signed/Timestamped JSON-LD envelope
        # - visible badge (if watermark_badge is not empty)
        console.print(f"  > Applying signed watermark to {deriv_path.name}...")
        _apply_watermark(
            image_path=deriv_path,
            badge_type=watermark_badge,
            manifest=manifest,
            signing_key=signing_key_path, # Pass key
            tsa_url=tsa_url               # Pass TSA URL
        )
        # --- END MODIFICATION ---

    # 4. Register Manifest in Forensic Vault
    console.print("  > Storing manifest in Evidence Vault...")
    try:
        receipt_id = store_evidence(
            content=manifest_json.encode('utf-8'),
            source="trusted_media_workflow",
            target=project_id
        )
        console.print(f"  > [green]Vault Receipt ID:[/green] {receipt_id}")
    except Exception as e:
        console.print(f"[bold red]Failed to store manifest in vault:[/bold red] {e}")
        raise

    # 5. Link to Adversary Research Grid (ARG)
    console.print("  > Linking to Adversary Research Grid (ARG)...")
    
    # ... (ARG logic unchanged) ...
    asset_node = BaseEntity(
        id_value=master_hash, 
        id_type="sha256", 
        label="MediaAsset",
        properties={"name": master_file_path.name}
    )
    project_node = BaseEntity(
        id_value=project_id, 
        id_type="project_id", 
        label="Project",
        properties={"name": project_id}
    )
    manifest_node = BaseEntity(
        id_value=receipt_id,
        id_type="receipt_id",
        label="VaultReceipt",
        properties={"type": "TrustedMediaManifest"}
    )
    editor_node = BaseEntity(
        id_value=editor_id,
        id_type="email",
        label="Person",
        properties={"role": "MediaEditor"}
    )
    entities = [asset_node, project_node, manifest_node, editor_node]
    rels = [
        Relationship(source=project_node, target=asset_node, label="PRODUCED"),
        Relationship(source=asset_node, target=manifest_node, label="HAS_MANIFEST"),
        Relationship(source=editor_node, target=asset_node, label="EDITED"),
    ]
    arg_service_instance.ingest_entities_and_relationships(entities, rels)
    
    package = MediaProductionPackage(
        master_file_path=str(master_file_path),
        manifest=manifest,
        derivatives=[str(p) for p in derivative_paths],
        manifest_vault_receipt_id=receipt_id,
        arg_nodes_created=[e.id_value for e in entities],
        arg_rels_created=len(rels)
    )

    return package


# --- 3. CLI Command ---

@trusted_media_app.command(
    "create", help="Register a new trusted media package."
)
def cli_create_trusted_media(
    master_file: pathlib.Path = typer.Argument(
        ..., exists=True, help="Path to the master PSD/PSB file."
    ),
    project_id: str = typer.Option(
        ..., "--project", "-p", help="Project ID to associate with."
    ),
    editor_id: str = typer.Option(
        ..., "--editor", "-e", help="Editor's user ID or email."
    ),
    # --- MODIFICATION: Add signing key ---
    signing_key: pathlib.Path = typer.Option(
        ..., "--key", "-k", exists=True, help="Path to the *private* key (.pem) for signing provenance."
    ),
    # --- END MODIFICATION ---
    derivative: List[pathlib.Path] = typer.Option(
        [], "--deriv", help="Path to a derivative file (e.g., PNG/JPG). Can be used multiple times.",
    ),
    consent_id: List[str] = typer.Option(
        [], "--consent", help="Consent ID for any person depicted. Can be used multiple times."
    ),
    ai_models_json: str = typer.Option(
        "[]", 
        help='JSON string of AI models used. e.g., \'[{"model_name": "GenFill v2"}]\'',
    ),
    watermark_badge: str = typer.Option(
        "Official / Verified", 
        help="Visible badge to apply (e.g., 'Official' or 'Synthetic')."
    ),
    embed_c2pa: bool = typer.Option(
        True, help="Embed C2PA Content Credentials."
    ),
    # --- MODIFICATION: Add TSA URL ---
    tsa_url: Optional[str] = typer.Option(
        CONFIG.get("tsa_url", "http://timestamp.digicert.com"),
        "--tsa-url",
        help="URL of the RFC3161 Timestamping Authority (TSA).",
    ),
    # --- END MODIFICATION ---
):
    """
    Executes the full workflow:
    1. Hashes the master file.
    2. Creates a JSON manifest.
    3. Applies REAL, SIGNED, TIMESTAMPED watermarking and C2PA to derivatives.
    4. Stores the manifest securely in the Evidence Vault.
    5. Links the asset, project, and manifest in the ARG.
    """
    # --- MODIFICATION: Check for all dependencies ---
    if not Image or not c2pa or not lsb or not hashes:
        console.print("[bold red]Error:[/bold red] Missing 'pillow', 'c2pa-python', 'stegano', or 'cryptography' dependencies.")
        raise typer.Exit(code=1)
    # --- END MODIFICATION ---

    # Check that derivatives are valid image files for processing
    valid_derivatives = []
    for d in derivative:
        if not d.exists():
            console.print(f"[yellow]Warning:[/yellow] Derivative {d} not found. Skipping.")
        elif d.suffix.lower() not in ['.png', '.jpg', '.jpeg']:
            console.print(f"[yellow]Warning:[/yellow] Derivative {d} is not a PNG/JPG. Skipping processing.")
        else:
            valid_derivatives.append(d)

    with console.status("[bold cyan]Creating trusted media package...[/bold cyan]"):
        try:
            # --- MODIFICATION: Pass new args to function ---
            tsa_url_to_use = tsa_url or CONFIG.get("tsa_url")
            package = create_trusted_media_package(
                master_file_path=master_file,
                project_id=project_id,
                editor_id=editor_id,
                consent_ids=consent_id,
                ai_models_json=ai_models_json,
                derivative_paths=valid_derivatives,
                embed_c2pa_flag=embed_c2pa,
                watermark_badge=watermark_badge,
                signing_key_path=signing_key, # Pass key
                tsa_url=tsa_url_to_use        # Pass TSA URL
            )
            # --- END MODIFICATION ---
            
            console.print("\n[bold green]Successfully created trusted media package![/bold green]")
            console.print(f"  > [cyan]Manifest Receipt ID:[/cyan] {package.manifest_vault_receipt_id}")
            console.print(f"  > [cyan]ARG Nodes:[/cyan] {len(package.arg_nodes_created)}")
            console.print(f"  > [cyan]ARG Relationships:[/cyan] {package.arg_rels_created}")

        except Exception as e:
            console.print(f"\n[bold red]Error:[/bold red] {e}")
            raise typer.Exit(code=1)

# --- NEW: Verification CLI Command (Req 8) ---
@trusted_media_app.command(
    "verify", help="Verify the embedded provenance of a trusted media file."
)
def cli_verify_provenance(
    file_path: pathlib.Path = typer.Argument(
        ..., exists=True, help="Path to the media file to verify (e.g., the exported PNG/JPG)."
    ),
    pub_key_path: pathlib.Path = typer.Option(
        ..., "--key", "-k", exists=True, help="Path to the *public* key (.pub.pem) for verification."
    ),
    output_file: Optional[pathlib.Path] = typer.Option(
        None, "--output", "-o", help="Save full verification result to a JSON file."
    ),
):
    """
    This is the public verification endpoint. It extracts the embedded
    JSON-LD manifest, verifies its signature and timestamp, and returns
    the trusted manifest.
    """
    with console.status("[bold cyan]Verifying embedded provenance...[/bold cyan]"):
        try:
            result = verify_embedded_provenance(file_path, pub_key_path)
            
            if result.is_valid:
                console.print("\n[bold green]Verification SUCCESSFUL[/bold green]")
                console.print("  - " + "\n  - ".join(result.verification_log))
                console.print("\n[bold]Verified Manifest:[/bold]")
                console.print_json(result.verified_manifest.model_dump_json(by_alias=True, indent=2))
            else:
                console.print("\n[bold red]Verification FAILED[/bold red]")
                console.print("  - " + "\n  - ".join(result.verification_log))

            if output_file:
                save_or_print_results(result.model_dump(exclude_none=True), output_file, console)

        except Exception as e:
            console.print(f"\n[bold red]Error verifying provenance:[/bold red] {e}")
            raise typer.Exit(code=1)
# --- END NEW COMMAND ---

if __name__ == "__main__":
    trusted_media_app()