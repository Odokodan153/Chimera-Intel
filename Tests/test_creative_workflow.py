"""
Tests for the Creative Asset Workflow module.
"""

import pytest
import json
import pathlib
import base64
from unittest.mock import MagicMock, patch, ANY

# Modules to be tested
from chimera_intel.core.creative_workflow import (
    CreativeAssetManifest,
    SignedCreativeEnvelope,
    export_and_sign_derivative,
    cli_export_psd
)

# Pydantic and Typer
from pydantic import ValidationError
from typer.testing import CliRunner

# --- Fixtures ---

@pytest.fixture
def mock_psd_image():
    """Mock fixture for a PSDImage object from psd-tools."""
    mock_img = MagicMock()
    # Mock PIL Image returned by composite()
    mock_pil_img = MagicMock(mode="RGBA")
    mock_pil_img.convert.return_value = mock_pil_img # Return self on convert
    mock_img.composite.return_value = mock_pil_img
    
    # Mock the manifest layer
    mock_layer = MagicMock()
    mock_layer.name = "PROVENANCE_MANIFEST"
    mock_layer.kind = "type"
    mock_layer.text = json.dumps({
        "origin_assets": ["master:original.psd"],
        "model_info": ["photoshop:v24.0"],
        "consent_ids": ["consent-abc"]
    })
    
    mock_img.__iter__.return_value = [mock_layer] # Make the image iterable
    return mock_img

@pytest.fixture
def mock_crypto_and_db():
    """Mocks all crypto, helper functions, and the database save function."""
    # Mock PIL Image.save
    with patch('PIL.Image.Image.save') as mock_pil_save, \
         patch('chimera_intel.core.creative_workflow.PSDImage') as mock_psdimage_class, \
         patch('chimera_intel.core.creative_workflow._load_private_key') as mock_load_key, \
         patch('chimera_intel.core.creative_workflow._get_timestamp_token') as mock_get_token, \
         patch('chimera_intel.core.creative_workflow._canonical_json_bytes') as mock_canonical_json, \
         patch('chimera_intel.core.creative_workflow.save_scan_to_db') as mock_save_db: # Mock the real db save
        
        # Mock the private key
        mock_key = MagicMock()
        mock_key.sign.return_value = b"mock_signature"
        mock_load_key.return_value = mock_key
        
        # Mock timestamping
        mock_get_token.return_value = (b"mock_tsa_token", MagicMock())
        
        # Mock json canonicalization
        mock_canonical_json.return_value = b'{"manifest": "data"}'
        
        yield {
            "save": mock_pil_save,
            "PSDImage": mock_psdimage_class,
            "load_key": mock_load_key,
            "get_token": mock_get_token,
            "sign": mock_key.sign,
            "save_scan_to_db": mock_save_db
        }

@pytest.fixture
def test_files(tmp_path):
    """Create dummy PSD and key files."""
    psd_file = tmp_path / "test_master.psd"
    psd_file.write_text("dummy_psd_content")
    
    key_file = tmp_path / "test_key.pem"
    key_file.write_text("dummy_key_content")
    
    return {"psd": psd_file, "key": key_file}


# --- Test Cases ---

def test_export_and_sign_derivative_png(mock_psd_image, mock_crypto_and_db, test_files):
    """Tests the full export pipeline for a PNG derivative."""
    
    # Configure the mock for psd_tools.open()
    mock_crypto_and_db["PSDImage"].open.return_value = mock_psd_image
    
    result = export_and_sign_derivative(
        psd_path=test_files["psd"],
        editor_id="editor-001",
        key_path=test_files["key"],
        output_format="png",
        consent_ids=["consent-xyz"],
        tsa_url="http://mock.tsa.com"
    )
    
    # 1. Check schemas
    assert isinstance(result.signed_envelope, SignedCreativeEnvelope)
    assert isinstance(result.signed_envelope.manifest, CreativeAssetManifest)
    
    # 2. Check manifest content
    manifest = result.signed_envelope.manifest
    assert manifest.file_name == "test_master.png"
    assert manifest.editor_id == "editor-001"
    assert manifest.sha256 is not None # Hash is calculated on-the-fly
    
    # 3. Check that manifest layer data was merged
    assert "master:original.psd" in manifest.origin_assets
    assert "photoshop:v24.0" in manifest.model_info
    
    # 4. Check that new consent_ids override layer data
    assert "consent-xyz" in manifest.consent_ids
    assert "consent-abc" not in manifest.consent_ids
    
    # 5. Check crypto calls
    mock_crypto_and_db["load_key"].assert_called_with(test_files["key"])
    mock_crypto_and_db["sign"].assert_called_with(b'{"manifest": "data"}', ANY, ANY)
    mock_crypto_and_db["get_token"].assert_called_with(b'{"manifest": "data"}', "http://mock.tsa.com")
    
    # 6. Check envelope content
    sig_b64 = base64.b64encode(b"mock_signature").decode("utf-8")
    tsa_b64 = base64.b64encode(b"mock_tsa_token").decode("utf-8")
    assert result.signed_envelope.signature == sig_b64
    assert result.signed_envelope.tsa_token_b64 == tsa_b64
    
    # 7. Check database calls
    mock_save_db = mock_crypto_and_db["save_scan_to_db"]
    assert mock_save_db.call_count == 2
    
    # Call 1: Save the derivative
    mock_save_db.assert_any_call(
        target="test_master.psd",
        module="creative_derivative",
        data={
            "file_name": "test_master.png",
            "logical_path": "creative_assets/derivatives/test_master.png",
            "format": "png",
            "editor_id": "editor-001",
            "b64_content": ANY # Check that content is being passed
        },
        scan_id=result.derivative_asset_id
    )
    
    # Call 2: Save the manifest
    mock_save_db.assert_any_call(
        target="test_master.psd",
        module="creative_manifest",
        data={
            "file_name": "test_master.png.manifest.json",
            "logical_path": "creative_assets/manifests/test_master.png.manifest.json",
            "derivative_asset_id": result.derivative_asset_id,
            "envelope": ANY # Check that envelope is being passed
        },
        scan_id=result.manifest_asset_id
    )
    assert result.derivative_logical_path == "creative_assets/derivatives/test_master.png"

def test_export_and_sign_derivative_jpg(mock_psd_image, mock_crypto_and_db, test_files):
    """Tests the JPG export path, including RGB conversion."""
    
    # Mock composite() to return an RGBA image, forcing conversion
    rgba_image = MagicMock(mode="RGBA")
    rgb_image = MagicMock(mode="RGB")
    rgba_image.convert.return_value = rgb_image
    mock_psd_image.composite.return_value = rgba_image
    
    mock_crypto_and_db["PSDImage"].open.return_value = mock_psd_image
    
    result = export_and_sign_derivative(
        psd_path=test_files["psd"],
        editor_id="editor-002",
        key_path=test_files["key"],
        output_format="jpg" # Request JPG
    )
    
    # Check that conversion to RGB was called
    rgba_image.convert.assert_called_with("RGB")
    
    # Check that PIL.save was called with "JPEG"
    mock_crypto_and_db["save"].assert_called_with(ANY, "JPEG", quality=95)
    
    # Check logical paths
    assert result.derivative_logical_path == "creative_assets/derivatives/test_master.jpg"
    assert result.manifest_logical_path == "creative_assets/manifests/test_master.jpg.manifest.json"
    
    # Check manifest filename
    assert result.signed_envelope.manifest.file_name == "test_master.jpg"

@patch('chimera_intel.core.creative_workflow.export_and_sign_derivative')
def test_cli_export_psd(mock_export_func, test_files, tmp_path):
    """Tests the Typer CLI command."""
    
    runner = CliRunner()
    
    # Mock the return value of the main function
    mock_result = MagicMock()
    mock_result.derivative_asset_id = "deriv-123"
    mock_result.manifest_asset_id = "manifest-123"
    mock_result.signed_envelope.manifest.sha256 = "abc...123"
    mock_export_func.return_value = mock_result
    
    output_json = tmp_path / "result.json"
    
    result = runner.invoke(
        cli_export_psd,
        [
            str(test_files["psd"]),
            "--key", str(test_files["key"]),
            "--editor", "cli-user-001",
            "--format", "png",
            "--consent-id", "cid-1",
            "--consent-id", "cid-2",
            "--output", str(output_json)
        ],
    )
    
    assert result.exit_code == 0
    assert "Creative Asset Export Successful" in result.stdout
    assert "deriv-123" in result.stdout
    assert "manifest-123" in result.stdout
    assert "abc...123" in result.stdout
    
    # Check that the main function was called correctly
    mock_export_func.assert_called_once_with(
        psd_path=test_files["psd"],
        editor_id="cli-user-001",
        key_path=test_files["key"],
        output_format="png",
        consent_ids=["cid-1", "cid-2"], # Check list creation
        tsa_url=ANY
    )
    
    # Check that the output file was written
    assert output_json.exists()
    assert '"derivative_asset_id": "deriv-123"' in output_json.read_text()