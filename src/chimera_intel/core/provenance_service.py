"""
Digital Provenance & Certification Service.

This module provides a unified service to embed and verify cryptographically
signed, timestamped provenance manifests (as JSON-LD) directly within
media files using steganography.

It implements the workflow for Forensic & Provenance Standard (Req 8):
1.  Creates a JSON-LD manifest (including consent IDs).
2.  Signs the manifest with a platform private key.
3.  Gets an RFC3161/TSA cryptographic timestamp for the manifest.
4.  Embeds the complete, signed "envelope" into the media file's LSB layer.
5.  Provides a public verification function to extract, verify, and return
    the manifest.

This module reuses signing/timestamping logic from 'forensic_vault.py'
and embedding logic from 'trusted_media.py'.
"""

import typer
import json
import pathlib
import logging
import hashlib
import base64
import httpx
from datetime import datetime, timezone
from typing import Optional, Tuple
from .schemas import (
    BaseModel,
    ProvenanceManifest,
    SignedProvenanceEnvelope,
    VerificationResult,
)
# --- Core Dependencies ---
try:
    from PIL import Image
except ImportError:
    Image = None

try:
    from stegano import lsb
except ImportError:
    lsb = None

try:
    import rfc3161
    from rfc3161 import Timestamper, get_tst_info, HASH_ALGORITHMS_BY_OID
except ImportError:
    rfc3161 = None

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
        load_pem_public_key,
        PrivateFormat,
        PublicFormat,
        NoEncryption,
    )
    from cryptography.exceptions import InvalidSignature
except ImportError:
    # Handle missing crypto dependencies
    rsa = None
    InvalidSignature = Exception

# --- Project Imports ---
from chimera_intel.core.schemas import BaseResult
from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.config_loader import CONFIG

# --- Setup ---
logger = logging.getLogger(__name__)
provenance_app = typer.Typer(
    name="provenance",
    help="Embed and verify signed, timestamped provenance in media.",
)

# --- Cryptographic Helpers (Reused from forensic_vault.py) ---

def _check_dependencies():
    """Check for all required libraries."""
    if not all([Image, lsb, rfc3161, rsa]):
        logger.critical("Missing dependencies. Please run: pip install pillow stegano rfc3161-client cryptography")
        raise typer.Exit(code=1)

def _load_private_key(key_path: pathlib.Path):
    """Loads a PEM private key for signing."""
    with open(key_path, "rb") as key_file:
        return load_pem_private_key(key_file.read(), password=None)

def _load_public_key(key_path: pathlib.Path):
    """Loads a PEM public key for verification."""
    with open(key_path, "rb") as key_file:
        return load_pem_public_key(key_file.read())

def _get_timestamp_token(
    data_bytes: bytes, tsa_url: str
) -> Tuple[Optional[bytes], Optional[datetime]]:
    """Requests an RFC3161 timestamp token for the given data."""
    try:
        timestamper = Timestamper(tsa_url, http_client=httpx.Client())
        ts_response = timestamper.timestamp(
            data=data_bytes, hash_algorithm="sha256"
        )
        timestamp = rfc3161.get_timestamp(ts_response)
        return ts_response, timestamp
    except Exception as e:
        logger.error(f"Failed to get timestamp from {tsa_url}: {e}")
        console.print(f"[bold red]Timestamping failed:[/bold red] {e}", style="stderr")
        return None, None

def _calculate_sha256(file_path: pathlib.Path) -> str:
    """Calculates the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def _canonical_json_bytes(data: BaseModel) -> bytes:
    """Serializes a Pydantic model to canonical (sorted) JSON bytes."""
    return data.model_dump_json(sort_keys=True, by_alias=True).encode("utf-8")

def _generate_keys(priv_path: pathlib.Path, pub_path: pathlib.Path):
    """Generates and saves a new RSA keypair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Write private key
    pem = private_key.private_bytes(
        encoding=hashes.serialization.Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption(),
    )
    with open(priv_path, "wb") as f: f.write(pem)
    # Write public key
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=hashes.serialization.Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    with open(pub_path, "wb") as f: f.write(pub_pem)

# --- Core Service Functions ---

def embed_signed_provenance(
    file_path: pathlib.Path,
    manifest_data: ProvenanceManifest,
    key_path: pathlib.Path,
    tsa_url: Optional[str] = None
) -> SignedProvenanceEnvelope:
    """
    Signs, timestamps, and embeds a provenance manifest into an image file.
    
    Args:
        file_path: Path to the original image file. Will be overwritten.
        manifest_data: The ProvenanceManifest object to embed.
        key_path: Path to the private PEM key for signing.
        tsa_url: Optional URL of an RFC3161 Timestamping Authority.
    
    Returns:
        The SignedProvenanceEnvelope that was embedded.
    """
    _check_dependencies()
    
    # 1. Load private key
    private_key = _load_private_key(key_path)
    
    # 2. Canonicalize the manifest to JSON bytes
    manifest_bytes = _canonical_json_bytes(manifest_data)
    
    # 3. Sign the manifest bytes
    signature = private_key.sign(
        manifest_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    sig_b64 = base64.b64encode(signature).decode("utf-8")

    # 4. Get optional timestamp for the manifest bytes
    tsa_token_b64 = None
    if tsa_url:
        ts_token_bytes, _ = _get_timestamp_token(manifest_bytes, tsa_url)
        if ts_token_bytes:
            tsa_token_b64 = base64.b64encode(ts_token_bytes).decode("utf-8")
        else:
            logger.warning("Failed to retrieve timestamp, proceeding without it.")

    # 5. Create the final envelope
    envelope = SignedProvenanceEnvelope(
        manifest=manifest_data,
        signature=sig_b64,
        tsa_token_b64=tsa_token_b64
    )
    envelope_json = envelope.model_dump_json(sort_keys=True, by_alias=True)
    
    # 6. Embed the envelope JSON into the image using LSB steganography
    try:
        img = Image.open(file_path)
        img_with_payload = lsb.hide(img, envelope_json)
        img_with_payload.save(file_path) # Overwrite original file
    except Exception as e:
        logger.error(f"Failed to embed payload into {file_path}: {e}")
        raise
        
    return envelope

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
    _check_dependencies()
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
            return VerificationResult(is_valid=False, verification_log=log)
        except Exception as e:
            log.append(f"Signature verification FAILED with error: {e}")
            return VerificationResult(is_valid=False, verification_log=log)
            
        # 5. Verify Timestamp (if present)
        if envelope.tsa_token_b64:
            try:
                ts_token_bytes = base64.b64decode(envelope.tsa_token_b64)
                tst_info = get_tst_info(ts_token_bytes)
                
                # Compare the hash inside the token with a recalculated hash
                ts_hash = tst_info["messageImprint"]["hashedMessage"]
                recalc_hash = hashlib.sha256(manifest_bytes).digest()
                
                if ts_hash == recalc_hash:
                    log.append(f"Timestamp VERIFIED. Trusted Time: {tst_info['genTime']}")
                else:
                    log.append("Timestamp HASH MISMATCH: Manifest does not match timestamped hash.")
                    return VerificationResult(is_valid=False, verification_log=log)
            except Exception as e:
                log.append(f"Timestamp verification FAILED with error: {e}")
                return VerificationResult(is_valid=False, verification_log=log)
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


# --- CLI ---

@provenance_app.command("generate-keys", help="Generate a new RSA keypair for signing.")
def cli_generate_keys(
    output_prefix: str = typer.Option(
        "provenance_key",
        "--output",
        "-o",
        help="Prefix for the key files (e.g., 'my_key').",
    ),
):
    """Generates 'prefix.pem' (private) and 'prefix.pub.pem' (public)."""
    priv_path = pathlib.Path(f"{output_prefix}.pem")
    pub_path = pathlib.Path(f"{output_prefix}.pub.pem")
    if priv_path.exists() or pub_path.exists():
        console.print(f"[bold red]Error:[/bold red] Files {priv_path} or {pub_path} already exist.")
        raise typer.Exit(code=1)
        
    _generate_keys(priv_path, pub_path)
    console.print(f"Private key saved to: {priv_path}")
    console.print(f"Public key saved to: {pub_path}")

@provenance_app.command("embed", help="Embed a signed, timestamped manifest into an image.")
def cli_embed_provenance(
    file_path: pathlib.Path = typer.Argument(..., exists=True, help="Path to the image file (will be overwritten)."),
    key_path: pathlib.Path = typer.Option(..., "--key", "-k", exists=True, help="Path to the private key (.pem) for signing."),
    issuer: str = typer.Option("Chimera-Intel", "--issuer", help="The 'issuer' name to embed in the manifest."),
    consent_id: Optional[str] = typer.Option(None, "--consent-id", help="Optional consent_artifact_id to link."),
    tsa_url: Optional[str] = typer.Option(CONFIG.get("tsa_url", "http://timestamp.digicert.com"), "--tsa-url", help="RFC3161 Timestamping Authority URL."),
):
    """
    Signs, timestamps, and embeds a JSON-LD manifest into a media file.
    """
    with console.status("[bold cyan]Embedding provenance...[/bold cyan]"):
        try:
            # 1. Calculate original hash
            console.print("  - Calculating original asset hash...")
            asset_hash = _calculate_sha256(file_path)
            
            # 2. Create manifest
            manifest = ProvenanceManifest(
                asset_hash=asset_hash,
                timestamp=datetime.now(timezone.utc).isoformat(),
                issuer=issuer,
                consent_artifact_id=consent_id,
                author=issuer # Use issuer for author field
            )
            console.print(f"  - Created manifest for asset hash: {asset_hash[:10]}...")
            
            # 3. Embed
            envelope = embed_signed_provenance(file_path, manifest, key_path, tsa_url)
            console.print("[green]Provenance successfully embedded![/green]")
            console.print(f"  - Signature: {envelope.signature[:30]}...")
            console.print(f"  - TSA Token: {'Yes' if envelope.tsa_token_b64 else 'No'}")
            
        except Exception as e:
            console.print(f"\n[bold red]Error embedding provenance:[/bold red] {e}")
            raise typer.Exit(code=1)

@provenance_app.command("verify", help="Verify the embedded provenance of a media file.")
def cli_verify_provenance(
    file_path: pathlib.Path = typer.Argument(..., exists=True, help="Path to the media file to verify."),
    pub_key_path: pathlib.Path = typer.Option(..., "--key", "-k", exists=True, help="Path to the *public* key (.pub.pem) for verification."),
    output_file: Optional[pathlib.Path] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """
    This is the public verification endpoint. It extracts the embedded
    manifest, verifies its signature and timestamp, and returns the
    trusted manifest.
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
                save_or_print_results(result.model_dump(exclude_none=True), output_file)

        except Exception as e:
            console.print(f"\n[bold red]Error verifying provenance:[/bold red] {e}")
            raise typer.Exit(code=1)

if __name__ == "__main__":
    provenance_app()