import os
import json
import logging
import hashlib
import typer
from rich import print
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List
from PIL import Image, ImageDraw, ImageFont
import numpy as np
import cv2
from imwatermark import WatermarkEncoder, WatermarkDecoder
import c2pa
from c2pa.manifest import Manifest
from c2pa.assertions import CreativeWork, Author
from c2pa.signing_options import SigningOptions, Signer

# --- Main Typer App ---
media_hardening_app = typer.Typer(
    name="harden",
    help="Manage defensive media hardening and provenance."
)

logger = logging.getLogger(__name__)

# --- Global Service Instance ---
# This instance is None by default and will be initialized by the plugin
# during the application's boot process.
media_hardening_service_instance: Optional['MediaHardeningService'] = None

def get_service() -> 'MediaHardeningService':
    """Typer dependency to get the initialized service instance."""
    if media_hardening_service_instance is None:
        print("[bold red]Error: MediaHardeningService is not initialized. Check plugin load and config.[/bold red]")
        raise typer.Exit(code=1)
    return media_hardening_service_instance


# --- Service Class (Business Logic) ---

class MediaHardeningService:
    """
    Provides services for hardening media assets, including watermarking,
    C2PA credentialing, controlled release, and OPSEC training briefs.
    """

    def __init__(self,
                 vault_path: str,
                 watermark_text: str,
                 opsec_brief_path: str,
                 c2pa_cert_path: str,
                 c2pa_key_path: str):
        
        self.vault_path = Path(vault_path)
        self.log_file = self.vault_path / "access_log.jsonl"
        self.watermark_text = watermark_text
        self.opsec_brief_path = Path(opsec_brief_path)
        
        if not self.vault_path.exists():
            self.vault_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Initialized secure media vault at: {self.vault_path}")

        # Initialize invisible watermark tools
        self.wm_encoder = WatermarkEncoder()
        self.wm_encoder.set_watermark('bytes', 'chimera-intel-provenance'.encode('utf-8'))
        self.wm_decoder = WatermarkDecoder('bytes', 192)

        # Load C2PA signer from configured production paths
        self.c2pa_signer = None
        try:
            self.c2pa_signer = Signer.from_files(c2pa_key_path, c2pa_cert_path)
            logger.info(f"Successfully loaded C2PA signer from: {c2pa_cert_path}")
        except Exception as e:
            logger.error(f"CRITICAL: Failed to load C2PA signer. "
                         f"Key={c2pa_key_path}, Cert={c2pa_cert_path}. Error: {e}")
            
        # Check for OPSEC brief file
        if not self.opsec_brief_path.exists():
             logger.error(f"CRITICAL: OPSEC brief file not found at: {opsec_brief_path}")

    def _log_vault_access(self, action: str, master_file: str, details: Dict[str, Any]):
        """Logs an action to the secure vault's access log."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "master_file": master_file,
            "details": details
        }
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

    def add_to_secure_vault(self, file_path: str, metadata: Dict[str, Any]) -> Optional[str]:
        # (Measure 4)
        source_path = Path(file_path)
        if not source_path.exists():
            logger.error(f"File not found: {file_path}")
            return None
        try:
            file_hash = hashlib.sha256(source_path.read_bytes()).hexdigest()
            destination_path = self.vault_path / f"{file_hash}_{source_path.name}"
            source_path.rename(destination_path)
            log_details = {
                "original_path": str(file_path),
                "vault_path": str(destination_path),
                "hash_sha256": file_hash,
                "metadata": metadata
            }
            self._log_vault_access("ADD_MASTER", destination_path.name, log_details)
            logger.info(f"Added master file {source_path.name} to vault.")
            return str(destination_path)
        except Exception as e:
            logger.error(f"Failed to add file {file_path} to vault: {e}")
            return None

    def release_public_thumbnail(self, master_hash_name: str, output_path: str, resolution: tuple = (800, 800)):
        # (Measure 1 & 4)
        master_path = self.vault_path / master_hash_name
        if not master_path.exists():
            logger.error(f"Master file not found in vault: {master_hash_name}")
            return None
        try:
            with Image.open(master_path) as img:
                img.thumbnail(resolution)
                img_with_watermark = self.apply_visible_watermark(img)
                img_with_watermark.save(output_path, "JPEG", quality=85)
                log_details = {
                    "public_file": output_path,
                    "resolution": resolution,
                    "watermarked": True
                }
                self._log_vault_access("RELEASE_PUBLIC", master_hash_name, log_details)
                logger.info(f"Released public thumbnail for {master_hash_name} to {output_path}")
                return output_path
        except Exception as e:
            logger.error(f"Failed to create thumbnail for {master_hash_name}: {e}")
            return None

    def apply_visible_watermark(self, image: Image.Image, text: Optional[str] = None) -> Image.Image:
        # (Measure 1 & 3)
        if text is None:
            text = self.watermark_text
        img_copy = image.convert("RGBA").copy()
        draw = ImageDraw.Draw(img_copy)
        try:
            font = ImageFont.truetype("arial.ttf", 40)
        except IOError:
            font = ImageFont.load_default()
        text_width, text_height = draw.textbbox((0, 0), text, font=font)[2:]
        width, height = img_copy.size
        x = width - text_width - 20
        y = height - text_height - 20
        draw.text((x, y), text, font=font, fill=(255, 255, 255, 128))
        return Image.alpha_composite(image.convert("RGBA"), img_copy)

    def embed_c2pa_credentials(self, image_path: str, output_path: str, author_name: str, claims: Dict[str, Any]) -> bool:
        # (Measure 2)
        if not self.c2pa_signer:
            logger.error("C2PA signer was not loaded successfully. Cannot embed credentials.")
            return False
        try:
            manifest = Manifest(
                "chimera-intel-asset",
                assertions=[CreativeWork().set_author([Author().set_name(author_name)])]
            )
            options = SigningOptions(self.c2pa_signer)
            c2pa.write_file(image_path, output_path, manifest, options)
            logger.info(f"Embedded C2PA credentials into {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to embed C2PA credentials: {e}")
            return False

    def verify_c2pa_credentials(self, image_path: str) -> Optional[Dict[str, Any]]:
        # (Measure 2)
        try:
            manifest_store = c2pa.read_file(image_path, "application/json")
            if not manifest_store:
                logger.info(f"No C2PA manifest found in {image_path}")
                return None
            return json.loads(manifest_store)
        except Exception as e:
            logger.error(f"Failed to verify C2PA credentials: {e}")
            return None

    def embed_invisible_watermark(self, image_path: str, output_path: str) -> bool:
        # (Measure 3)
        try:
            bgr = cv2.imread(image_path)
            if bgr is None:
                raise ValueError(f"Could not read image: {image_path}")
            bgr_wm = self.wm_encoder.encode(bgr, 'dwtDct')
            cv2.imwrite(output_path, bgr_wm)
            logger.info(f"Embedded invisible watermark in {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to embed invisible watermark: {e}")
            return False

    def verify_invisible_watermark(self, image_path: str) -> bool:
        # (Measure 3)
        try:
            bgr = cv2.imread(image_path)
            if bgr is None:
                raise ValueError(f"Could not read image: {image_path}")
            watermark = self.wm_decoder.decode(bgr, 'dwtDct')
            if watermark == b'chimera-intel-provenance':
                logger.info(f"Provenance VERIFIED for {image_path}")
                return True
            else:
                logger.warning(f"Provenance FAILED for {image_path}")
                return False
        except Exception as e:
            logger.error(f"Failed to verify invisible watermark: {e}")
            return False

    def get_opsec_training_brief(self) -> Optional[Dict[str, List[str]]]:
        # (Measure 5)
        if not self.opsec_brief_path.exists():
            logger.error(f"OPSEC brief file not found at: {self.opsec_brief_path}")
            return None
        try:
            with open(self.opsec_brief_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load or parse OPSEC brief file: {e}")
            return None


# --- Typer CLI Commands ---

@media_hardening_app.command(name="vault-add", help="(M4) Add a master file to the secure vault.")
def vault_add(
    ctx: typer.Context,
    file_path: Path = typer.Argument(..., help="Path to the master file.", exists=True, readable=True),
    owner: str = typer.Option("unknown", help="Metadata: Owner of the file."),
    classification: str = typer.Option("CUI", help="Metadata: Classification level.")
):
    """Adds a master file to the secure vault."""
    service = get_service()
    metadata = {"owner": owner, "classification": classification}
    vault_path = service.add_to_secure_vault(str(file_path), metadata)
    if vault_path:
        print(f"[green]Successfully added file to vault:[/green] {vault_path}")
    else:
        print(f"[red]Failed to add file to vault.[/red]")
        raise typer.Exit(code=1)

@media_hardening_app.command(name="release-public", help="(M1, M4) Release a low-res, watermarked image.")
def release_public(
    ctx: typer.Context,
    master_name: str = typer.Argument(..., help="The hashed name of the master file in the vault."),
    output_path: Path = typer.Argument(..., help="Path to save the public-facing image."),
    width: int = typer.Option(800, help="Max width of the public image."),
    height: int = typer.Option(800, help="Max height of the public image.")
):
    """Releases a public-facing, watermarked thumbnail from a vault master."""
    service = get_service()
    result = service.release_public_thumbnail(master_name, str(output_path), resolution=(width, height))
    if result:
        print(f"[green]Public image released to:[/green] {result}")
    else:
        print(f"[red]Failed to release public image.[/red]")
        raise typer.Exit(code=1)

@media_hardening_app.command(name="c2pa-embed", help="(M2) Embed C2PA Content Credentials.")
def c2pa_embed(
    ctx: typer.Context,
    image_path: Path = typer.Argument(..., help="Path to the input image.", exists=True, readable=True),
    output_path: Path = typer.Argument(..., help="Path to save the C2PA-enabled image."),
    author: str = typer.Option("Chimera-Intel", help="Author name to embed.")
):
    """Embeds C2PA (Content Credentials) into an image."""
    service = get_service()
    if not service.c2pa_signer:
        print("[red]C2PA signer is not configured or failed to load. Check config.yaml.[/red]")
        raise typer.Exit(code=1)
    
    print(f"Embedding C2PA credentials from [cyan]{author}[/cyan] into {image_path}...")
    success = service.embed_c2pa_credentials(str(image_path), str(output_path), author, {})
    if success:
        print(f"[green]Successfully created C2PA-enabled file:[/green] {output_path}")
    else:
        print(f"[red]Failed to embed C2PA credentials.[/red]")
        raise typer.Exit(code=1)

@media_hardening_app.command(name="c2pa-verify", help="(M2) Verify C2PA Content Credentials.")
def c2pa_verify(
    ctx: typer.Context,
    image_path: Path = typer.Argument(..., help="Path to the image to verify.", exists=True, readable=True)
):
    """Verifies C2PA (Content Credentials) in an image."""
    service = get_service()
    manifest = service.verify_c2pa_credentials(str(image_path))
    if manifest:
        print(f"[green]C2PA Manifest VERIFIED:[/green]")
        print(json.dumps(manifest, indent=2))
    else:
        print(f"[yellow]No valid C2PA manifest found.[/yellow]")

@media_hardening_app.command(name="opsec-brief", help="(M5) Get employee OPSEC training brief.")
def opsec_brief(
    ctx: typer.Context
):
    """Displays the configured employee OPSEC training brief."""
    service = get_service()
    brief = service.get_opsec_training_brief()
    if not brief:
        print("[red]Could not load OPSEC brief. Check file path in config.yaml.[/red]")
        raise typer.Exit(code=1)
        
    print(f"--- [bold cyan]{brief.get('title', 'OPSEC Brief')}[/bold cyan] ---")
    modules = brief.get('modules', {})
    if not modules:
        print("[yellow]Brief content is empty or malformed.[/yellow]")
        return
        
    for module_name, points in modules.items():
        print(f"\n[yellow][ {module_name.replace('_', ' ').title()} ][/yellow]")
        for point in points:
            print(f"- {point}")