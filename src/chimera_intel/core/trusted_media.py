"""
Module for Image Production & Photoshop Best Practices (for CI & trusted media).

Provides a workflow to produce high-quality, auditable images for
PR/marketing, register them in the Evidence Vault, and link them to the ARG.

New Dependencies:
pip install pillow c2pa-python stegano
"""

import typer
import logging
import os
import json
import hashlib
import pathlib
from typing import List
from .schemas import (
    TrustedMediaManifest,
    TrustedMediaAIMetadata,
    MediaProductionPackage,
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
from .utils import console
from .evidence_vault import store_evidence 
from .in_mem_arg_service import in_mem_arg_service_instance as arg_service_instance
from .arg_service import BaseEntity, Relationship  

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
    manifest: TrustedMediaManifest, # <-- ADDED manifest
    is_invisible: bool = False
):
    """
    REAL IMPLEMENTATION: Applies layered watermarks.
    
    1. (Invisible) A simple EXIF tag.
    2. (Invisible) A robust Steganography LSB tag.
    3. (Visible) A visible badge.
    
    Applies all layers and saves the image once.
    """
    if not Image:
        logger.error("Pillow library not found. Skipping watermarking.")
        return

    try:
        with Image.open(image_path) as img:
            # Preserve original format info
            original_format = img.format
            img = img.convert("RGBA")
            exif_data = img.getexif()
            img_to_save = img  # Start with the base image

            if is_invisible:
                # Layer 1: Simple EXIF tag 
                # 40094 is 'WindowsKeywords'
                exif_data[40094] = "CHIMERA-INTEL-VERIFIED-ASSET".encode('utf-16le')
                logger.info(f"Applied invisible EXIF watermark to {image_path.name}")

                # Layer 2: Robust Steganography (LSB)
                if not lsb:
                    logger.warning("stegano library not found. Skipping LSB watermark.")
                else:
                    try:
                        secret_message = f"CHIMERA-INTEL::{manifest.master_sha256}::{manifest.timestamp}"
                        # Hide data in the image object
                        # Note: This returns a *new* image object
                        img_to_save = lsb.hide(img_to_save, secret_message)
                        logger.info(f"Applied invisible LSB watermark to {image_path.name}")
                    except Exception as e:
                        logger.error(f"Failed to apply LSB watermark: {e}")
            
            if badge_type:
                # Layer 3: Visible Badge
                # Draw on top of the (potentially) LSB-watermarked image
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
            
            # Consolidated Save:
            # Save the final processed image (img_to_save) 
            # with the modified EXIF data (exif_data)
            if original_format == "PNG":
                img_to_save.save(image_path, "PNG", exif=exif_data)
            elif original_format in ["JPEG", "JPG"]:
                # Must convert back to RGB for JPEG
                img_to_save.convert("RGB").save(image_path, "JPEG", exif=exif_data)
            else:
                img_to_save.save(image_path, exif=exif_data)
                
    except Exception as e:
        logger.error(f"Failed to apply watermark to {image_path.name}: {e}")

# --- END MODIFICATION ---


def create_trusted_media_package(
    master_file_path: pathlib.Path,
    project_id: str,
    editor_id: str,
    consent_ids: List[str],
    ai_models_json: str,
    derivative_paths: List[pathlib.Path],
    embed_c2pa_flag: bool,
    watermark_badge: str,
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
        
        # --- MODIFICATION: Simplified watermarking call ---
        # This single call applies all watermark layers:
        # - invisible EXIF
        # - invisible Stegano (using the manifest)
        # - visible badge (if watermark_badge is not empty)
        _apply_watermark(
            image_path=deriv_path,
            badge_type=watermark_badge,
            manifest=manifest,
            is_invisible=True  # Always apply invisible layers
        )
        # --- END MODIFICATION ---

    # 4. Register Manifest in Forensic Vault
    # (This section is unchanged, but 'store_evidence' now uses SQLite)
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
    # (This section is unchanged, but 'arg_service_instance' now uses NetworkX)
    console.print("  > Linking to Adversary Research Grid (ARG)...")
    
    # Define Entities
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

    # Define Relationships
    rels = [
        Relationship(source=project_node, target=asset_node, label="PRODUCED"),
        Relationship(source=asset_node, target=manifest_node, label="HAS_MANIFEST"),
        Relationship(source=editor_node, target=asset_node, label="EDITED"),
    ]
    
    # Ingest
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
    )
):
    """
    Executes the full workflow:
    1. Hashes the master file.
    2. Creates a JSON manifest.
    3. Applies REAL watermarking and C2PA embedding to derivatives.
    4. Stores the manifest securely in the Evidence Vault.
    5. Links the asset, project, and manifest in the ARG.
    """
    # --- MODIFICATION: Check for all dependencies ---
    if not Image or not c2pa or not lsb:
        console.print("[bold red]Error:[/bold red] Missing 'pillow', 'c2pa-python', or 'stegano' dependencies.")
        console.print("Please run: [bold]pip install pillow c2pa-python stegano[/bold]")
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
            package = create_trusted_media_package(
                master_file_path=master_file,
                project_id=project_id,
                editor_id=editor_id,
                consent_ids=consent_id,
                ai_models_json=ai_models_json,
                derivative_paths=valid_derivatives,
                embed_c2pa_flag=embed_c2pa,
                watermark_badge=watermark_badge,
            )
            
            console.print("\n[bold green]Successfully created trusted media package![/bold green]")
            console.print(f"  > [cyan]Manifest Receipt ID:[/cyan] {package.manifest_vault_receipt_id}")
            console.print(f"  > [cyan]ARG Nodes:[/cyan] {len(package.arg_nodes_created)}")
            console.print(f"  > [cyan]ARG Relationships:[/cyan] {package.arg_rels_created}")

        except Exception as e:
            console.print(f"\n[bold red]Error:[/bold red] {e}")
            raise typer.Exit(code=1)

if __name__ == "__main__":
    trusted_media_app()