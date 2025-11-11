# Tests/test_provenance_embedding.py

import pytest
import pathlib
import json
import base64
import hashlib
from datetime import datetime, timezone
from typing import Tuple

# Dependency imports
from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.exceptions import InvalidSignature

# Modules to test
from chimera_intel.core.trusted_media import (
    _apply_watermark, 
    verify_embedded_provenance,
    TrustedMediaManifest
)
from chimera_intel.core.forensic_vault import _generate_keys, _calculate_sha256
from chimera_intel.core.schemas import ProvenanceManifest, _canonical_json_bytes

# --- Fixtures ---

@pytest.fixture(scope="module")
def key_pair(tmp_path_factory) -> Tuple[pathlib.Path, pathlib.Path]:
    """Generates a new RSA keypair for the test session."""
    tmp_path = tmp_path_factory.mktemp("keys")
    priv_path = tmp_path / "test_key.pem"
    pub_path = tmp_path / "test_key.pub.pem"
    _generate_keys(priv_path, pub_path)
    return priv_path, pub_path

@pytest.fixture
def sample_image(tmp_path: pathlib.Path) -> pathlib.Path:
    """Creates a fresh, blank PNG image for each test."""
    img_path = tmp_path / "test_image.png"
    img = Image.new('RGB', (100, 100), color='blue')
    img.save(img_path)
    return img_path

@pytest.fixture
def sample_manifest(sample_image: pathlib.Path) -> TrustedMediaManifest:
    """Creates a sample TrustedMediaManifest."""
    # Calculate hash of the *original* image
    master_hash = _calculate_sha256(sample_image)
    
    return TrustedMediaManifest(
        master_sha256=master_hash,
        source_files=[str(sample_image)],
        editor_id="test_editor@chimera.ai",
        ai_models_used=[],
        consent_ids=["consent-12345"],
        project_id="project-orion",
        author="Test Author"
    )

# --- Tests ---

def test_embed_and_verify_workflow(key_pair, sample_image, sample_manifest, mocker):
    """
    Tests the full embed-and-verify workflow by modifying trusted_media.py
    and mocking the TSA.
    """
    priv_key, pub_key = key_pair
    
    # 1. Mock the network call to the TSA
    mock_tsa = mocker.patch("chimera_intel.core.trusted_media._get_timestamp_token")
    mock_tsa.return_value = (b"dummy_tsa_token_bytes", datetime.now(timezone.utc))

    # 2. Mock the TSA *verification* logic
    # We need to make get_tst_info return the correct hash
    
    # Re-create the expected manifest that _apply_watermark will build
    expected_prov_manifest = ProvenanceManifest(
        asset_hash=sample_manifest.master_sha256,
        timestamp=sample_manifest.timestamp,
        issuer=sample_manifest.author,
        consent_artifact_id=sample_manifest.consent_ids[0],
        author=sample_manifest.author
    )
    manifest_bytes = _canonical_json_bytes(expected_prov_manifest)
    expected_hash = hashlib.sha256(manifest_bytes).digest()
    
    mock_get_info = mocker.patch("chimera_intel.core.trusted_media.get_tst_info")
    mock_get_info.return_value = {
        "messageImprint": {
            "hashedMessage": expected_hash,
            "hashAlgorithm": {"algorithm": "2.16.840.1.101.3.4.2.1"} # OID for sha256
        },
        "genTime": datetime.now(timezone.utc)
    }

    # 3. Call the modified _apply_watermark function
    tsa_url = "http://fake.tsa.com"
    _apply_watermark(
        image_path=sample_image,
        badge_type="Verified",
        manifest=sample_manifest,
        signing_key=priv_key,
        tsa_url=tsa_url
    )
    
    mock_tsa.assert_called_once_with(manifest_bytes, tsa_url)
    
    # 4. Verify the provenance using the new public function
    result = verify_embedded_provenance(sample_image, pub_key)
    
    # 5. Assertions
    assert result.is_valid is True
    assert result.verified_manifest == expected_prov_manifest
    assert result.verified_manifest.consent_artifact_id == "consent-12345"
    assert "Signature VERIFIED." in result.verification_log
    assert "Timestamp VERIFIED." in result.verification_log

def test_verify_fails_with_tampered_image(key_pair, sample_image, sample_manifest, mocker):
    """
    Tests that verification fails if the image is modified *after* embedding.
    """
    priv_key, pub_key = key_pair
    
    # 1. Mock TSA
    mocker.patch("chimera_intel.core.trusted_media._get_timestamp_token", return_value=(None, None))
    
    # 2. Embed provenance
    _apply_watermark(
        image_path=sample_image,
        badge_type="Verified",
        manifest=sample_manifest,
        signing_key=priv_key,
        tsa_url=None
    )
    
    # 3. Tamper with the image (draw a line on it)
    img = Image.open(sample_image)
    draw = ImageDraw.Draw(img)
    draw.line((0, 0, 100, 100), fill='red', width=5)
    img.save(sample_image)
    
    # 4. Verify
    result = verify_embedded_provenance(sample_image, pub_key)
    
    # 5. Assertions
    # The LSB data is likely corrupted by the modification
    assert result.is_valid is False
    assert (
        "Verification FAILED: Failed to decode payload." in result.verification_log[0] or
        "Signature VERIFICATION FAILED" in result.verification_log[0]
    )

def test_verify_no_tsa_token(key_pair, sample_image, sample_manifest, mocker):
    """
    Tests that verification succeeds (for signature) even if no TSA token was
    embedded.
    """
    priv_key, pub_key = key_pair
    
    # 1. Mock the TSA to *fail*
    mocker.patch("chimera_intel.core.trusted_media._get_timestamp_token", return_value=(None, None))
    
    # 2. Embed provenance
    _apply_watermark(
        image_path=sample_image,
        badge_type="Verified",
        manifest=sample_manifest,
        signing_key=priv_key,
        tsa_url="http://fake.tsa.com" # Try to use TSA
    )
    
    # 3. Verify
    result = verify_embedded_provenance(sample_image, pub_key)
    
    # 4. Assertions
    assert result.is_valid is True # Signature is still valid
    assert "Signature VERIFIED." in result.verification_log
    assert "Timestamp: SKIPPED (No token present in payload)." in result.verification_log