"""
Tests for the Trusted Media workflow module.
"""

import pytest
import json
import hashlib
import pathlib
import os
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, ANY

# --- Mock dependencies *before* they are imported by the module
# This ensures that even if 'pip install' failed, the tests can run
import sys
mock_pil = MagicMock()
mock_pil.Image = MagicMock()
mock_pil.ImageDraw = MagicMock()
mock_pil.ImageFont = MagicMock()

mock_c2pa = MagicMock()
mock_c2pa.sign_file = MagicMock()
mock_c2pa.create_signer.from_files = MagicMock()
mock_c2pa.Signer = MagicMock()

sys.modules['PIL'] = mock_pil
sys.modules['PIL.Image'] = mock_pil.Image
sys.modules['PIL.ImageDraw'] = mock_pil.ImageDraw
sys.modules['PIL.ImageFont'] = mock_pil.ImageFont
sys.modules['c2pa'] = mock_c2pa

# Now import the module to be tested
from chimera_intel.core.trusted_media import (
    trusted_media_app, 
    create_trusted_media_package,
    _calculate_sha256,
    _apply_watermark,
    _embed_c2pa,
    TrustedMediaManifest
)

# --- Real Pillow/C2PA for integration-style tests ---
# We try to import them again for real testing
# If they fail, we skip the tests that need them
try:
    from PIL import Image, ImageFont, ExifTags
    import c2pa as real_c2pa
    pillow_installed = True
except ImportError:
    pillow_installed = False

# Fixture for the CLI runner
@pytest.fixture
def runner():
    return CliRunner()

# Fixture to create temporary master and derivative files
@pytest.fixture
def temp_media_files(tmp_path):
    master_file = tmp_path / "product_X_v1.psd"
    master_content = b"dummy_psd_master_content_abc123"
    master_file.write_bytes(master_content)
    
    # Create a *real* PNG derivative file
    deriv_file = tmp_path / "product_X_web.png"
    if pillow_installed:
        img = Image.new('RGB', (100, 100), color = 'blue')
        img.save(deriv_file, 'PNG')
    else:
        deriv_file.write_bytes(b"dummy_png_content") # Fallback
    
    # Calculate expected hash
    expected_hash = hashlib.sha256(master_content).hexdigest()
    
    yield master_file, deriv_file, expected_hash


# Mock the external dependencies (Vault and ARG)
@pytest.fixture(autouse=True)
def mock_external_services():
    with patch("chimera_intel.core.trusted_media.store_evidence") as mock_store, \
         patch("chimera_intel.core.trusted_media.arg_service_instance") as mock_arg, \
         patch("chimera_intel.core.trusted_media.c2pa", new=mock_c2pa), \
         patch("chimera_intel.core.trusted_media.Image", new=mock_pil.Image), \
         patch("chimera_intel.core.trusted_media.ImageDraw", new=mock_pil.ImageDraw), \
         patch("chimera_intel.core.trusted_media.ImageFont", new=mock_pil.ImageFont):
        
        # Configure mocks
        mock_store.return_value = "receipt-id-for-manifest-12345"
        mock_arg.ingest_entities_and_relationships = MagicMock()
        
        # Configure PIL mocks
        mock_img_instance = MagicMock()
        mock_img_instance.getexif.return_value = {}
        mock_pil.Image.open.return_value.__enter__.return_value = mock_img_instance
        
        yield mock_store, mock_arg, mock_c2pa, mock_pil

def test_calculate_sha256_helper(temp_media_files):
    master_file, _, expected_hash = temp_media_files
    assert _calculate_sha256(master_file) == expected_hash

# This test uses the mocks to ensure the logic flows correctly
def test_create_trusted_media_package_logic(temp_media_files, mock_external_services):
    master_file, deriv_file, expected_hash = temp_media_files
    mock_store, mock_arg, mock_c2pa_lib, mock_pil_lib = mock_external_services
    
    ai_json = '[{"model_name": "GenFill v2", "prompt": "remove background"}]'
    
    package = create_trusted_media_package(
        master_file_path=master_file,
        project_id="Project-Orion",
        editor_id="editor@chimera.corp",
        consent_ids=["consent-person-A"],
        ai_models_json=ai_json,
        derivative_paths=[deriv_file],
        embed_c2pa_flag=True,
        watermark_badge="Official / Verified"
    )

    # 1. Verify the returned package object
    assert package.manifest_vault_receipt_id == "receipt-id-for-manifest-12345"
    assert package.manifest.master_sha256 == expected_hash
    assert package.manifest.project_id == "Project-Orion"

    # 2. Verify Evidence Vault call
    mock_store.assert_called_once()
    stored_content_bytes = mock_store.call_args[1]['content']
    assert json.loads(stored_content_bytes.decode('utf-8'))['editor_id'] == "editor@chimera.corp"

    # 3. Verify ARG service call
    mock_arg.ingest_entities_and_relationships.assert_called_once()
    entities = mock_arg.ingest_entities_and_relationships.call_args[0][0]
    entity_ids = {e.id_value for e in entities}
    assert expected_hash in entity_ids
    assert "Project-Orion" in entity_ids

    # 4. Verify C2PA and Watermark calls
    mock_c2pa_lib.sign_file.assert_called_once()
    assert mock_pil_lib.Image.open.call_count == 2 # Called once for invisible, once for visible

@pytest.mark.skipif(not pillow_installed, reason="Pillow (PIL) is not installed")
def test_real_apply_watermark(temp_media_files):
    """
    Tests the *real* watermarking function using a real temp image.
    This test does *not* use the PIL mocks.
    """
    _, deriv_file, _ = temp_media_files
    
    # 1. Test invisible watermark (EXIF)
    _apply_watermark(deriv_file, badge_type="", is_invisible=True)
    
    with Image.open(deriv_file) as img:
        exif_data = img.getexif()
        # 40094 is 'WindowsKeywords'
        keyword_tag = 40094
        assert keyword_tag in exif_data
        assert exif_data[keyword_tag].decode('utf-16le') == "CHIMERA-INTEL-VERIFIED-ASSET"

    # 2. Test visible watermark (Pixel check)
    # Get original file size to compare
    original_size = os.path.getsize(deriv_file)

    _apply_watermark(deriv_file, badge_type="TEST BADGE", is_invisible=False)
    
    new_size = os.path.getsize(deriv_file)
    assert new_size != original_size # Image data has changed
    
    with Image.open(deriv_file) as img:
        # Check if bottom-right pixel is no longer blue (it's covered by the badge)
        bottom_right_pixel = img.getpixel((99, 99))
        assert bottom_right_pixel != (0, 0, 255) # Original blue


@pytest.mark.skipif(not pillow_installed, reason="C2PA and Pillow are not installed")
def test_real_embed_c2pa(temp_media_files, tmp_path):
    """
    Tests the *real* C2PA function using a real temp image.
    This test does *not* use the C2PA mocks.
    """
    # This test needs the *real* module references
    from chimera_intel.core.trusted_media import _embed_c2pa as real_embed_c2pa_func
    
    _, deriv_file, _ = temp_media_files
    manifest = TrustedMediaManifest(
        master_sha256="dummy_hash",
        editor_id="test@chimera.corp",
        project_id="Test-Project-C2PA"
    )
    
    # Create a dummy signer in the temp path
    with patch("chimera_intel.core.trusted_media.pathlib.Path") as mock_path:
        # Make the signer path point to our temp directory
        mock_signer_path = tmp_path / "c2pa_signer"
        mock_signer_path.mkdir()
        mock_path.return_value = mock_signer_path
        
        # Call the real signer creation
        real_c2pa.create_signer.from_files(
            sign_cert_path=mock_signer_path / "sign.crt",
            private_key_path=mock_signer_path / "sign.key",
            out_dir=mock_signer_path,
        )

        original_size = os.path.getsize(deriv_file)
        
        # Call the real C2PA embedding function
        success = real_embed_c2pa_func(deriv_file, manifest)
        
        assert success is True
        
        # Check that the file was modified (C2PA adds data)
        new_size = os.path.getsize(deriv_file)
        assert new_size > original_size

# Test the CLI command
def test_trusted_media_cli_command(runner, temp_media_files, mock_external_services):
    master_file, deriv_file, _ = temp_media_files
    mock_store, mock_arg, mock_c2pa_lib, mock_pil_lib = mock_external_services

    ai_json_cli = '[{"model_name": "GenFill v2"}]'

    result = runner.invoke(
        trusted_media_app,
        [
            "create",
            str(master_file),
            "--project", "Project-Apollo",
            "--editor", "user@chimera.corp",
            "--deriv", str(deriv_file),
            "--consent", "consent-A",
            "--ai-models-json", ai_json_cli,
        ],
        catch_exceptions=False # Show full traceback on error
    )
    
    assert result.exit_code == 0
    assert "Successfully created trusted media package" in result.stdout
    assert "receipt-id-for-manifest-12345" in result.stdout
    
    # Verify mocks were called
    mock_store.assert_called_once()
    mock_arg.ingest_entities_and_relationships.assert_called_once()
    
    # Verify C2PA and Watermark mocks were called
    mock_c2pa_lib.sign_file.assert_called_once()
    mock_pil_lib.Image.open.assert_called()