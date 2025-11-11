# Tests/test_provenance_service.py

import pytest
import pathlib
from stegano import lsb
import hashlib
from datetime import datetime, timezone
from typing import Tuple

# Dependency imports
from PIL import Image


# Module to test
from chimera_intel.core.provenance_service import (
    embed_signed_provenance,
    verify_embedded_provenance,
    _generate_keys,
    ProvenanceManifest,
    _canonical_json_bytes
)

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

# --- Tests ---

def test_embed_and_verify_workflow(key_pair, sample_image, mocker):
    """
    Tests the full embed-and-verify workflow with mocked TSA.
    """
    priv_key, pub_key = key_pair
    
    # 1. Define the manifest to embed
    manifest = ProvenanceManifest(
        asset_hash="dummy_hash_for_test", # Hash is calculated inside the CLI, but we pass it here
        timestamp=datetime.now(timezone.utc).isoformat(),
        issuer="TestIssuer",
        consent_artifact_id="consent-12345"
    )
    
    # 2. Mock the network call to the TSA
    mock_tsa = mocker.patch("chimera_intel.core.provenance_service._get_timestamp_token")
    mock_tsa.return_value = (b"dummy_tsa_token_bytes", datetime.now(timezone.utc))

    # 3. Mock the TSA *verification* logic
    # We need to make get_tst_info return the correct hash
    manifest_bytes = _canonical_json_bytes(manifest)
    expected_hash = hashlib.sha256(manifest_bytes).digest()
    
    mock_get_info = mocker.patch("chimera_intel.core.provenance_service.get_tst_info")
    mock_get_info.return_value = {
        "messageImprint": {
            "hashedMessage": expected_hash,
            "hashAlgorithm": {"algorithm": "2.16.840.1.101.3.4.2.1"} # OID for sha256
        },
        "genTime": datetime.now(timezone.utc)
    }

    # 4. Embed the provenance
    tsa_url = "http://fake.tsa.com"
    embed_signed_provenance(sample_image, manifest, priv_key, tsa_url)
    
    mock_tsa.assert_called_once_with(manifest_bytes, tsa_url)
    
    # 5. Verify the provenance
    result = verify_embedded_provenance(sample_image, pub_key)
    
    # 6. Assertions
    assert result.is_valid is True
    assert result.verified_manifest == manifest
    assert "Signature VERIFIED." in result.verification_log
    assert "Timestamp VERIFIED." in result.verification_log

def test_verify_fails_with_wrong_key(key_pair, sample_image, mocker, tmp_path_factory):
    """
    Tests that verification fails if the wrong public key is used.
    """
    priv_key, pub_key = key_pair
    
    # 1. Generate a *second* key pair
    wrong_key_path = tmp_path_factory.mktemp("wrong_keys")
    wrong_priv_key, wrong_pub_key = (
        wrong_key_path / "wrong.pem",
        wrong_key_path / "wrong.pub.pem",
    )
    _generate_keys(wrong_priv_key, wrong_pub_key)
    
    # 2. Mock TSA (not strictly necessary for this test, but good practice)
    mocker.patch("chimera_intel.core.provenance_service._get_timestamp_token", 
                 return_value=(b"dummy_token", datetime.now(timezone.utc)))
    
    # 3. Embed with the *correct* private key
    manifest = ProvenanceManifest(
        asset_hash="hash1", timestamp=datetime.now(timezone.utc).isoformat(), issuer="Test"
    )
    embed_signed_provenance(sample_image, manifest, priv_key, "http://fake.tsa.com")

    # 4. Verify with the *wrong* public key
    result = verify_embedded_provenance(sample_image, wrong_pub_key)
    
    # 5. Assertions
    assert result.is_valid is False
    assert result.verified_manifest is None
    assert "Signature VERIFICATION FAILED: Signature does not match manifest." in result.verification_log

def test_verify_fails_with_tampered_timestamp(key_pair, sample_image, mocker):
    """
    Tests that verification fails if the timestamp hash doesn't match the manifest hash.
    """
    priv_key, pub_key = key_pair
    
    manifest = ProvenanceManifest(
        asset_hash="hash1", timestamp=datetime.now(timezone.utc).isoformat(), issuer="Test"
    )
    
    # 1. Mock TSA embed
    mocker.patch("chimera_intel.core.provenance_service._get_timestamp_token", 
                 return_value=(b"dummy_tsa_token_bytes", datetime.now(timezone.utc)))
    
    # 2. Mock TSA *verification* to return a *wrong* hash
    mock_get_info = mocker.patch("chimera_intel.core.provenance_service.get_tst_info")
    mock_get_info.return_value = {
        "messageImprint": {
            "hashedMessage": b"this_is_a_bad_hash",
            "hashAlgorithm": {"algorithm": "2.16.840.1.101.3.4.2.1"}
        },
        "genTime": datetime.now(timezone.utc)
    }

    # 3. Embed
    embed_signed_provenance(sample_image, manifest, priv_key, "http://fake.tsa.com")
    
    # 4. Verify
    result = verify_embedded_provenance(sample_image, pub_key)
    
    # 5. Assertions
    assert result.is_valid is False
    assert "Signature VERIFIED." in result.verification_log # Signature is correct
    assert "Timestamp HASH MISMATCH: Manifest does not match timestamped hash." in result.verification_log

def test_verify_no_payload(sample_image, key_pair):
    """
    Tests that verification fails gracefully if no payload is present.
    """
    _, pub_key = key_pair
    
    # 1. Verify a clean, unmodified image
    result = verify_embedded_provenance(sample_image, pub_key)
    
    # 2. Assertions
    assert result.is_valid is False
    assert "Verification FAILED: No embedded payload found." in result.verification_log

def test_verify_corrupt_payload(sample_image, key_pair):
    """
    Tests that verification fails gracefully if the payload is not valid JSON.
    """
    _, pub_key = key_pair
    
    # 1. Embed junk data into the image
    img = Image.open(sample_image)
    img_with_junk = lsb.hide(img, "This is not JSON")
    img_with_junk.save(sample_image)
    
    # 2. Verify
    result = verify_embedded_provenance(sample_image, pub_key)
    
    # 3. Assertions
    assert result.is_valid is False
    assert "Verification FAILED: Failed to decode payload." in result.verification_log[0]