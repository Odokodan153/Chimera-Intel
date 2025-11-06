import pytest
import os
import shutil
import json
from pathlib import Path
from PIL import Image
import numpy as np
from datetime import datetime, timedelta

# --- Dependencies for "real" test setup ---
# These libraries would need to be installed for testing:
# pip install pytest cryptography
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("WARNING: 'cryptography' library not found. C2PA tests will fail.")
    x509 = None
# --- End Dependencies ---

# Ensure the core module is in the path
try:
    from chimera_intel.core.media_hardening import MediaHardeningService
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
    from chimera_intel.core.media_hardening import MediaHardeningService


# --- Fixtures ---

TEST_VAULT_DIR = "test_vault"
TEST_OUTPUT_DIR = "test_output"
DUMMY_IMAGE_NAME = "dummy_master.png"
DUMMY_IMAGE_LOWRES = "dummy_public.jpg"
DUMMY_IMAGE_C2PA = "dummy_c2pa.jpg"
DUMMY_IMAGE_INV_WM = "dummy_inv_wm.png"

# --- Helper function to generate test certs ---
def generate_test_certs(key_path: Path, cert_path: Path):
    if not x509:
        raise ImportError("Cryptography library is required to generate test certs.")

    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Write private key
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Generate self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"TestState"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"TestCity"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TestOrg"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"test.chimera.intel"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256(), default_backend())

    # Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

@pytest.fixture(scope="module")
def setup_test_environment():
    """Create test dirs, dummy image, dummy brief, and dummy certs."""
    vault_path = Path(TEST_VAULT_DIR)
    output_path = Path(TEST_OUTPUT_DIR)
    vault_path.mkdir(exist_ok=True)
    output_path.mkdir(exist_ok=True)

    # 1. Create a dummy high-res image
    img_path = output_path / DUMMY_IMAGE_NAME
    img = Image.new('RGB', (2048, 2048), color='blue')
    img.save(img_path)

    # 2. Create dummy OPSEC brief
    opsec_brief_path = output_path / "test_opsec_brief.json"
    brief_content = {
        "title": "Test Brief",
        "modules": {"test_module": ["Test point 1."]}
    }
    with open(opsec_brief_path, 'w') as f:
        json.dump(brief_content, f)

    # 3. Generate dummy C2PA certs and keys
    key_path = output_path / "test.key"
    cert_path = output_path / "test.crt"
    try:
        generate_test_certs(key_path, cert_path)
    except Exception as e:
        pytest.skip(f"Could not generate test certs, skipping C2PA tests. Error: {e}")

    # 4. Initialize service with "real" paths to test files
    service = MediaHardeningService(
        vault_path=TEST_VAULT_DIR,
        watermark_text="TEST WATERMARK",
        opsec_brief_path=str(opsec_brief_path),
        c2pa_cert_path=str(cert_path),
        c2pa_key_path=str(key_path)
    )

    yield service, img_path

    # --- Teardown ---
    print("\nTearing down test environment...")
    shutil.rmtree(TEST_VAULT_DIR, ignore_errors=True)
    shutil.rmtree(TEST_OUTPUT_DIR, ignore_errors=True)

# --- Tests ---

def test_1_add_to_secure_vault(setup_test_environment):
    service, img_path = setup_test_environment
    
    metadata = {"owner": "test_user", "classification": "HIGH"}
    vault_file_path_str = service.add_to_secure_vault(str(img_path), metadata)
    
    assert vault_file_path_str is not None
    vault_file_path = Path(vault_file_path_str)
    
    # 1. Check if file exists in vault
    assert vault_file_path.exists()
    
    # 2. Check if original file is gone (it was moved)
    assert not img_path.exists()
    
    # 3. Check if log file was written
    assert service.log_file.exists()
    with open(service.log_file, 'r') as f:
        log_entry = json.loads(f.readline())
        
    assert log_entry["action"] == "ADD_MASTER"
    assert log_entry["master_file"] == vault_file_path.name
    assert log_entry["details"]["metadata"]["owner"] == "test_user"

def test_2_release_public_thumbnail(setup_test_environment):
    service, _ = setup_test_environment
    
    # We must use the file added in the previous test
    vault_files = list(service.vault_path.glob("*.png"))
    assert len(vault_files) > 0
    master_hash_name = vault_files[0].name
    
    output_thumb_path = Path(TEST_OUTPUT_DIR) / DUMMY_IMAGE_LOWRES
    
    result_path = service.release_public_thumbnail(master_hash_name, str(output_thumb_path), resolution=(100, 100))
    
    assert result_path is not None
    assert output_thumb_path.exists()
    
    # Check if image is smaller
    with Image.open(output_thumb_path) as thumb:
        assert thumb.size == (100, 100)
        
    # Check log
    with open(service.log_file, 'r') as f:
        lines = f.readlines()
    log_entry = json.loads(lines[-1]) # Get last log entry
    assert log_entry["action"] == "RELEASE_PUBLIC"
    assert log_entry["details"]["public_file"] == str(output_thumb_path)

def test_3_get_opsec_training_brief(setup_test_environment):
    service, _ = setup_test_environment
    brief = service.get_opsec_training_brief()
    
    assert brief is not None
    assert "title" in brief
    assert brief["title"] == "Test Brief"
    assert "modules" in brief
    assert "test_module" in brief["modules"]
    assert brief["modules"]["test_module"][0] == "Test point 1."

def test_4_invisible_watermark(setup_test_environment):
    service, _ = setup_test_environment
    # Use the public thumbnail as input
    input_img_path = Path(TEST_OUTPUT_DIR) / DUMMY_IMAGE_LOWRES
    output_img_path = Path(TEST_OUTPUT_DIR) / DUMMY_IMAGE_INV_WM
    
    assert input_img_path.exists()

    # Embed
    embed_success = service.embed_invisible_watermark(str(input_img_path), str(output_img_path))
    assert embed_success
    assert output_img_path.exists()
    
    # Verify
    verify_success = service.verify_invisible_watermark(str(output_img_path))
    assert verify_success

def test_5_c2pa_credentials(setup_test_environment):
    service, _ = setup_test_environment
    # Use the public thumbnail as input
    input_img_path = Path(TEST_OUTPUT_DIR) / DUMMY_IMAGE_LOWRES
    output_img_path = Path(TEST_OUTPUT_DIR) / DUMMY_IMAGE_C2PA
    
    assert input_img_path.exists()

    # Embed
    claims = {"info": "Test asset for Chimera Intel"}
    embed_success = service.embed_c2pa_credentials(str(input_img_path), str(output_img_path), "Chimera-Intel Bot", claims)
    assert embed_success
    assert output_img_path.exists()
    
    # Verify
    manifest_store = service.verify_c2pa_credentials(str(output_img_path))
    assert manifest_store is not None
    assert "manifests" in manifest_store
    assert "adobe.com.chimera-intel-asset" in manifest_store["manifests"]
    assert "CreativeWork" in manifest_store["manifests"]["adobe.com.chimera-intel-asset"]["assertions"]