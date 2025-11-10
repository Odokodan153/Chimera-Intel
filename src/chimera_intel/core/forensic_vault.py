# Chimera-Intel/src/chimera_intel/core/forensic_vault.py
"""
Module for Advanced Image Forensics, Attribution, and Secure Vaulting.

Provides tools for:
1.  Image Hashing (pHash, dHash) for similarity analysis.
2.  Reverse Image Search (Attribution) using Google Vision API.
3.  Forensic Vaulting (Signing & Timestamping) for chain of custody.
4.  Exporting verified derivatives of master files.

NOTE ON DEPENDENCIES:
This module requires new libraries:
pip install imagehash google-cloud-vision rfc3161 cryptography pillow
"""

import typer
import json
import pathlib
import logging
import hashlib
import base64
import httpx
from datetime import datetime
from typing import Optional, Tuple
from PIL import Image
from rich.console import Console
# Hashing
import imagehash
# Reverse Image Search
from google.cloud import vision

# Signing & Timestamping
import rfc3161
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

# Project Imports
from .schemas import (
    ImageHashResult,
    ReverseImageMatch,
    ReverseImageSearchResult,
    VaultReceipt,
    VaultExportResult,)
from .utils import save_or_print_results
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)
console = Console()
vault_app = typer.Typer(
    name="vault",
    help="Advanced Forensics: Image Hashing, Reverse Search & Forensic Vault",
)


# --- 1. Image Hashing (Similarity) ---

def calculate_image_hashes(image_path: pathlib.Path) -> ImageHashResult:
    """
    Calculates the pHash and dHash for a given image.
    """
    try:
        img = Image.open(image_path)
        p_hash = str(imagehash.phash(img))
        d_hash = str(imagehash.dhash(img))
        return ImageHashResult(file_path=str(image_path), phash=p_hash, dhash=d_hash)
    except Exception as e:
        return ImageHashResult(
            file_path=str(image_path), error=f"Could not process image: {e}"
        )


@vault_app.command("hash-image", help="Calculate perceptual and difference hashes (pHash, dHash).")
def cli_hash_image(
    file_path: pathlib.Path = typer.Argument(
        ..., exists=True, help="Path to the image file."
    ),
    output_file: Optional[pathlib.Path] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes an image to produce pHash and dHash values for similarity
    comparisons and database lookups (e.g., in FAISS).
    """
    result = calculate_image_hashes(file_path)
    save_or_print_results(result.model_dump(exclude_none=True), output_file)


# --- 2. Reverse Image Search (Attribution) ---

def reverse_image_search(image_path: pathlib.Path) -> ReverseImageSearchResult:
    """
    Uses the Google Vision API to perform a reverse image search (Web Detection).
    """
    api_key = API_KEYS.google_api_key
    if not api_key:
        return ReverseImageSearchResult(
            file_path=str(image_path),
            error="GOOGLE_API_KEY not found in .env file."
        )
    
    # We must set the API key credentials for the vision client
    client_options = {"api_key": api_key}
    client = vision.ImageAnnotatorClient(client_options=client_options)

    try:
        with open(image_path, "rb") as image_file:
            content = image_file.read()

        image = vision.Image(content=content)
        response = client.web_detection(image=image)
        web_detection = response.web_detection

        result = ReverseImageSearchResult(file_path=str(image_path))

        if web_detection.best_guess_labels:
            result.best_guess = web_detection.best_guess_labels[0].label

        if web_detection.pages_with_matching_images:
            for page in web_detection.pages_with_matching_images:
                result.matches.append(
                    ReverseImageMatch(url=page.url, title=page.page_title)
                )

        if response.error.message:
            raise Exception(response.error.message)

        return result

    except Exception as e:
        return ReverseImageSearchResult(
            file_path=str(image_path), error=f"Google Vision API error: {e}"
        )


@vault_app.command("reverse-search", help="Perform reverse image search (attribution).")
def cli_reverse_search(
    file_path: pathlib.Path = typer.Argument(
        ..., exists=True, help="Path to the image file."
    ),
    output_file: Optional[pathlib.Path] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Uses Google Vision API to find sources and similar images on the web.
    """
    console.print(f"Performing reverse image search for: {file_path}")
    result = reverse_image_search(file_path)
    save_or_print_results(result.model_dump(exclude_none=True), output_file)


# --- 3. Forensic Vault (Signing & Timestamping) ---

def _generate_metadata_hash(file_path: pathlib.Path, creation_time: datetime) -> Tuple[str, str, bytes]:
    """Helper to create and hash file metadata."""
    file_bytes = file_path.read_bytes()
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    
    # Create the metadata object that we will sign
    metadata = {
        "file_path": str(file_path.name),
        "file_hash": file_hash,
        "hash_algorithm": "sha256",
        "created_at": creation_time.isoformat(),
    }
    metadata_bytes = json.dumps(metadata, sort_keys=True).encode("utf-8")
    metadata_hash = hashlib.sha256(metadata_bytes).hexdigest()
    
    return file_hash, metadata_hash, metadata_bytes


def _get_timestamp_token(
    data_bytes: bytes, tsa_url: str
) -> Tuple[Optional[bytes], Optional[datetime]]:
    """Requests an RFC3161 timestamp token for the given data."""
    try:
        timestamper = rfc3161.Timestamper(tsa_url, http_client=httpx.Client())
        ts_response = timestamper.timestamp(
            data=data_bytes, hash_algorithm="sha256"
        )
        timestamp = rfc3161.get_timestamp(ts_response)
        return ts_response, timestamp
    except Exception as e:
        logger.error(f"Failed to get timestamp from {tsa_url}: {e}")
        console.print(f"[bold red]Timestamping failed:[/bold red] {e}", style="stderr")
        return None, None


def create_vault_receipt(
    file_path: pathlib.Path,
    key_path: pathlib.Path,
    tsa_url: Optional[str] = "http://timestamp.digicert.com",
) -> VaultReceipt:
    """
    Internal function to create a signed and timestamped receipt.
    This is refactored from cli_create_receipt to be reusable.
    """
    # 1. Load Private Key
    with open(key_path, "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), password=None)

    # 2. Get Timestamp (optional)
    # We get the timestamp *first* to use as the official "created_at" time
    ts_token_b64 = None
    timestamp = None
    
    # We need *a* creation time, even if timestamping fails
    creation_time = datetime.now(datetime.UTC)

    if tsa_url:
        console.print(f"  - Requesting timestamp from {tsa_url}...")
        # We timestamp a preliminary hash of the file path and time
        # This is a bit of a chicken-and-egg problem.
        # Let's timestamp the *metadata* after it's created.
        pass # We'll do this after step 3
    
    # 3. Create and hash metadata
    file_hash, metadata_hash, metadata_bytes = _generate_metadata_hash(file_path, creation_time)
    console.print(f"  - File Hash (sha256): {file_hash}")
    console.print(f"  - Metadata Hash (sha256): {metadata_hash}")

    # 4. Sign the metadata bytes (not the hash, to be more robust)
    signature = private_key.sign(
        metadata_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    sig_b64 = base64.b64encode(signature).decode("utf-8")
    console.print(f"  - Signature created.")

    # 5. Get Timestamp (now for real, on the metadata bytes)
    if tsa_url:
        ts_token_bytes, timestamp_from_tsa = _get_timestamp_token(metadata_bytes, tsa_url)
        if ts_token_bytes:
            ts_token_b64 = base64.b64encode(ts_token_bytes).decode("utf-8")
            # Use the trusted time from the TSA
            timestamp = timestamp_from_tsa
            console.print(f"  - Timestamp received: {timestamp}")
        else:
            console.print(f"  - [yellow]Could not get timestamp. Using local time.[/yellow]")
            timestamp = creation_time
    else:
        timestamp = creation_time

    # 6. Create receipt object
    receipt = VaultReceipt(
        file_path=str(file_path.name),
        file_hash=file_hash,
        metadata_hash=metadata_hash,
        signature=sig_b64,
        timestamp_token=ts_token_b64,
        timestamp=timestamp,
    )
    return receipt


@vault_app.command("create-receipt", help="Create a signed, timestamped forensic receipt.")
def cli_create_receipt(
    file_path: pathlib.Path = typer.Argument(
        ..., exists=True, help="Path to the evidence file to sign."
    ),
    key_path: pathlib.Path = typer.Option(
        ...,
        "--key",
        "-k",
        exists=True,
        help="Path to the private key (.pem) for signing.",
    ),
    tsa_url: Optional[str] = typer.Option(
        "http://timestamp.digicert.com",
        "--tsa-url",
        help="URL of the RFC3161 Timestamping Authority (TSA).",
    ),
    output_file: Optional[pathlib.Path] = typer.Option(
        None, "--output", "-o", help="Save receipt to a JSON file (e.g., 'receipt.json')."
    ),
):
    """
    Creates a Forensic Vault Receipt.
    This hashes the file, wraps the hash in signed metadata,
    and gets a trusted timestamp for the metadata.
    """
    console.print(f"Creating receipt for: {file_path}")
    try:
        receipt = create_vault_receipt(file_path, key_path, tsa_url)
        save_or_print_results(receipt.model_dump(exclude_none=True), output_file)
    except Exception as e:
        console.print(f"[bold red]Error creating receipt:[/bold red] {e}")
        raise typer.Exit(code=1)


@vault_app.command("verify-receipt", help="Verify a forensic receipt against a file.")
def cli_verify_receipt(
    receipt_path: pathlib.Path = typer.Argument(
        ..., exists=True, help="Path to the receipt.json file."
    ),
    key_path: pathlib.Path = typer.Option(
        ...,
        "--key",
        "-k",
        exists=True,
        help="Path to the *public* key (.pub.pem) for verification.",
    ),
    file_path: Optional[pathlib.Path] = typer.Option(
        None,
        "--file",
        "-f",
        exists=True,
        help="Path to the original file. If not provided, will look for it based on receipt.",
    ),
):
    """
    Verifies the integrity and authenticity of a file against its
    Forensic Vault Receipt.
    """
    try:
        # 1. Load Receipt and Public Key
        with open(receipt_path, "r") as f:
            receipt_data = json.load(f)
            # Parse timestamp string back into datetime object
            if receipt_data.get("timestamp"):
                receipt_data["timestamp"] = datetime.fromisoformat(receipt_data["timestamp"])
            receipt = VaultReceipt(**receipt_data)
        
        with open(key_path, "rb") as f:
            public_key = load_pem_public_key(f.read())

        # 2. Find and check original file
        if not file_path:
            file_path = receipt_path.parent / receipt.file_path
        
        if not file_path.exists():
            console.print(f"[bold red]Error:[/bold red] Original file not found at {file_path}")
            raise typer.Exit(code=1)

        console.print(f"Verifying {file_path.name} against {receipt_path.name}...")
        
        # 3. Verify File Hash
        file_bytes = file_path.read_bytes()
        recalc_file_hash = hashlib.sha256(file_bytes).hexdigest()
        
        if recalc_file_hash == receipt.file_hash:
            console.print("  - File Hash: [bold green]VERIFIED[/bold green]")
        else:
            console.print("  - File Hash: [bold red]FAILED[/bold red]")
            raise typer.Exit(code=1)

        # 4. Recreate metadata and verify signature
        if not receipt.timestamp:
             console.print("[bold yellow]Warning:[/bold yellow] Cannot verify signature without timestamp 'created_at'. Skipping.")
             raise typer.Exit(code=1)

        metadata_to_verify = {
            "file_path": str(receipt.file_path),
            "file_hash": receipt.file_hash,
            "hash_algorithm": "sha256",
            "created_at": receipt.timestamp.isoformat(),
        }
        metadata_bytes_to_verify = json.dumps(metadata_to_verify, sort_keys=True).encode("utf-8")
        
        try:
            public_key.verify(
                base64.b64decode(receipt.signature),
                metadata_bytes_to_verify,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            console.print("  - Signature: [bold green]VERIFIED[/bold green]")
        except InvalidSignature:
            console.print("  - Signature: [bold red]FAILED[/bold red]")
            console.print(f"  - Metadata for verification: {metadata_to_verify}")
            raise typer.Exit(code=1)

        # 5. Verify Timestamp
        if receipt.timestamp_token:
            ts_token_bytes = base64.b64decode(receipt.timestamp_token)
            tst_info = rfc3161.get_tst_info(ts_token_bytes)
            
            # Extract timestamped hash
            ts_hash_algo_obj = tst_info["messageImprint"]["hashAlgorithm"]
            # Convert OID to a recognizable name if possible, default to OID
            ts_hash_algo_name = rfc3161.HASH_ALGORITHMS_BY_OID.get(ts_hash_algo_obj["algorithm"], ts_hash_algo_obj["algorithm"])
            ts_hash = tst_info["messageImprint"]["hashedMessage"]
            
            # Recalculate hash of metadata bytes that *should* have been timestamped
            recalc_meta_hash = hashlib.sha256(metadata_bytes_to_verify).digest()

            if ts_hash == recalc_meta_hash:
                console.print(f"  - Timestamp: [bold green]VERIFIED[/bold green] (Algorithm: {ts_hash_algo_name})")
                console.print(f"    - Trusted Time: {tst_info['genTime']}")
            else:
                console.print("  - Timestamp: [bold red]FAILED[/bold red] (Hash mismatch)")
        
        console.print("\n[bold green]Verification successful.[/bold green]")

    except Exception as e:
        console.print(f"[bold red]Verification failed:[/bold red] {e}")
        raise typer.Exit(code=1)


# --- 4. Export & Delivery (NEW FUNCTION) ---

@vault_app.command("export-derivative", help="Export a flattened, receipted derivative (JPG/PNG).")
def cli_export_derivative(
    file_path: pathlib.Path = typer.Argument(
        ..., exists=True, help="Path to the master evidence file (e.g., .psd, .tiff, .png)."
    ),
    key_path: pathlib.Path = typer.Option(
        ...,
        "--key",
        "-k",
        exists=True,
        help="Path to the private key (.pem) for signing the *new* receipt.",
    ),
    output_format: str = typer.Option(
        "png",
        "--format",
        "-f",
        help="Output format: 'png' or 'jpg'.",
    ),
    output_path: Optional[pathlib.Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Path for the exported file. [default: <original_name>.<format>]"
    ),
    tsa_url: Optional[str] = typer.Option(
        "http://timestamp.digicert.com",
        "--tsa-url",
        help="URL of the RFC3161 Timestamping Authority (TSA).",
    ),
):
    """
    Exports a derivative of a master file (e.g., PSD to PNG),
    calculates hashes of both the original and the new file,
    and creates a new Forensic Vault Receipt for the exported derivative.
    """
    console.print(f"Exporting derivative for: {file_path}")
    
    # 1. Validate format and determine output path
    export_format = output_format.lower()
    if export_format not in ["png", "jpg"]:
        console.print("[bold red]Error:[/bold red] Output format must be 'png' or 'jpg'.")
        raise typer.Exit(code=1)
        
    if not output_path:
        output_path = file_path.with_suffix(f".{export_format}")

    try:
        # 2. Load and export image
        img = Image.open(file_path)
        
        if export_format == "jpg":
            # Ensure RGB mode for JPG
            if img.mode != "RGB":
                img = img.convert("RGB")
            img.save(output_path, "JPEG", quality=95)
        else:
            # PNG supports transparency
            img.save(output_path, "PNG")
            
        console.print(f"  - Exported file saved to: {output_path}")

        # 3. Calculate hashes
        original_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        exported_hash = hashlib.sha256(output_path.read_bytes()).hexdigest()
        
        console.print(f"  - Original Hash (SHA256): {original_hash}")
        console.print(f"  - Exported Hash (SHA256): {exported_hash}")

        # 4. Create a new receipt for the exported file
        console.print(f"Creating receipt for new derivative: {output_path.name}")
        exported_receipt = create_vault_receipt(output_path, key_path, tsa_url)

        # 5. Create final result object
        export_result = VaultExportResult(
            original_file=str(file_path.name),
            original_hash_sha256=original_hash,
            exported_file=str(output_path.name),
            exported_hash_sha256=exported_hash,
            export_format=export_format,
            exported_receipt=exported_receipt
        )
        
        # 6. Save result
        receipt_output_path = output_path.with_suffix(f".{export_format}.receipt.json")
        save_or_print_results(
            export_result.model_dump(exclude_none=True),
            receipt_output_path
        )
        console.print(f"Export process complete. Result receipt saved to: {receipt_output_path}")

    except Exception as e:
        console.print(f"[bold red]Error during export:[/bold red] {e}")
        raise typer.Exit(code=1)


# --- 5. Key Generation ---

@vault_app.command("generate-key", help="Generate a new RSA keypair for signing.")
def cli_generate_key(
    output_prefix: str = typer.Option(
        "signing_key",
        "--output",
        "-o",
        help="Prefix for the key files (e.g., 'my_key').",
    ),
):
    """Generates 'prefix.pem' (private) and 'prefix.pub.pem' (public)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    
    # Write private key
    priv_path = f"{output_prefix}.pem"
    pem = private_key.private_bytes(
        encoding=hashes.serialization.Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption(),
    )
    with open(priv_path, "wb") as f:
        f.write(pem)
    console.print(f"Private key saved to: {priv_path}")

    # Write public key
    pub_path = f"{output_prefix}.pub.pem"
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=hashes.serialization.Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    console.print(f"Public key saved to: {pub_path}")


if __name__ == "__main__":
    vault_app()