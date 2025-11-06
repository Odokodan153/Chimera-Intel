# Chimera-Intel/Tests/test_forensic_vault.py
import unittest
import os
import json
import pathlib
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from PIL import Image
from datetime import datetime, timezone
import hashlib
# Module to test
from chimera_intel.core.forensic_vault import (
    vault_app,
    calculate_image_hashes,
    ImageHashResult
)
from chimera_intel.core.config_loader import API_KEYS

# Mock timestamping response data
MOCK_TSA_URL = "http://mock.tsa.com"
MOCK_DATETIME = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
MOCK_TS_TOKEN_B64 = "dG9rZW4="  # "token"
MOCK_TS_RESPONSE_BYTES = b"dummy_ts_response_bytes"

# Pre-calculate hash for the solid blue image
# content = Image.new("RGB", (100, 100), color="blue").tobytes()
# hashlib.sha256(content).hexdigest() -> 'a8f7d050c567a2167815b3f2f83c0f66b17a637a1f53630f48b111e813f875f0'
BLUE_IMG_SHA256 = "a8f7d050c567a2167815b3f2f83c0f66b17a637a1f53630f48b111e813f875f0"


class TestForensicVault(unittest.TestCase):
    """Test cases for the Forensic Vault & Advanced IMINT module."""

    def setUp(self):
        """Set up a test environment."""
        self.runner = CliRunner()
        self.test_dir = pathlib.Path("test_vault_data")
        self.test_dir.mkdir(exist_ok=True)
        
        # Create a dummy image file (using PNG to test conversion)
        self.dummy_image_path = self.test_dir / "test_image.png"
        Image.new("RGB", (100, 100), color="blue").save(self.dummy_image_path, "PNG")
        
        # Create a dummy keypair
        self.key_prefix = self.test_dir / "test_key"
        self.priv_key_path = self.test_dir / "test_key.pem"
        self.pub_key_path = self.test_dir / "test_key.pub.pem"
        result = self.runner.invoke(vault_app, ["generate-key", "--output", str(self.key_prefix)])
        self.assertEqual(result.exit_code, 0)
        
        self.receipt_path = self.test_dir / "test.receipt.json"

    def tearDown(self):
        """Clean up test files."""
        for f in self.test_dir.glob("*"):
            os.remove(f)
        os.rmdir(self.test_dir)

    # --- Test 1: Image Hashing ---
    
    def test_calculate_image_hashes_success(self):
        """Tests successful calculation of pHash and dHash."""
        result = calculate_image_hashes(self.dummy_image_path)
        self.assertIsInstance(result, ImageHashResult)
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.phash)
        self.assertEqual(result.phash, "c3c3c3c3c3c3c3c3") # Hash for solid blue
        self.assertEqual(result.dhash, "0000000000000000") # Hash for solid blue

    def test_cli_hash_image(self):
        """Tests the 'hash-image' CLI command."""
        result = self.runner.invoke(vault_app, ["hash-image", str(self.dummy_image_path)])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("c3c3c3c3c3c3c3c3", result.stdout)
        self.assertIn("0000000000000000", result.stdout)

    # --- Test 2: Reverse Image Search (Mocked API) ---

    @patch("chimera_intel.core.forensic_vault.vision.ImageAnnotatorClient")
    def test_cli_reverse_search_success(self, mock_vision_client):
        """Tests the 'reverse-search' CLI command with a mocked API."""
        # Arrange
        API_KEYS.google_api_key = "fake_key"
        mock_client_inst = mock_vision_client.return_value
        
        # Create a mock response structure
        mock_label = MagicMock()
        mock_label.label = "Blue Square"
        mock_page = MagicMock()
        mock_page.url = "http://example.com/blue-square"
        mock_page.page_title = "Example Page"
        
        mock_web_detection = MagicMock()
        mock_web_detection.best_guess_labels = [mock_label]
        mock_web_detection.pages_with_matching_images = [mock_page]
        
        mock_response = MagicMock()
        mock_response.web_detection = mock_web_detection
        mock_response.error.message = None
        mock_client_inst.web_detection.return_value = mock_response

        # Act
        result = self.runner.invoke(vault_app, ["reverse-search", str(self.dummy_image_path)])

        # Assert
        self.assertEqual(result.exit_code, 0)
        mock_client_inst.web_detection.assert_called_once()
        self.assertIn("Blue Square", result.stdout)
        self.assertIn("http://example.com/blue-square", result.stdout)

    # --- Test 3: Forensic Vault (Real Signing, Mocked Timestamping) ---
    
    @patch("chimera_intel.core.forensic_vault.datetime")
    @patch("chimera_intel.core.forensic_vault._get_timestamp_token")
    def test_cli_create_and_verify_receipt(self, mock_get_timestamp, mock_datetime):
        """
        Tests creating a receipt (with real signing, mocked timestamping)
        and then successfully verifying it.
        """
        # --- 1. CREATE RECEIPT ---
        
        # Arrange mock for timestamping
        mock_datetime.now.return_value = MOCK_DATETIME
        mock_get_timestamp.return_value = (MOCK_TS_RESPONSE_BYTES, MOCK_DATETIME)

        # Act
        create_result = self.runner.invoke(
            vault_app,
            [
                "create-receipt",
                str(self.dummy_image_path),
                "--key",
                str(self.priv_key_path),
                "--tsa-url",
                MOCK_TSA_URL,
                "--output",
                str(self.receipt_path),
            ],
        )
        
        # Assert creation
        self.assertEqual(create_result.exit_code, 0)
        self.assertTrue(self.receipt_path.exists())
        mock_get_timestamp.assert_called_once()
        
        with open(self.receipt_path, "r") as f:
            receipt_data = json.load(f)
        
        self.assertEqual(
            receipt_data["timestamp"], MOCK_DATETIME.isoformat()
        )
        self.assertIsNotNone(receipt_data["signature"])
        # Verify the file hash of the blue PNG
        self.assertEqual(receipt_data["file_hash"], BLUE_IMG_SHA256)


        # --- 2. VERIFY RECEIPT ---
        
        # Arrange mock for verification
        # We need to mock the verification part of the timestamp
        with patch("chimera_intel.core.forensic_vault.rfc3161.get_tst_info") as mock_get_tst_info:
            
            # Recreate the metadata bytes that *would* have been timestamped
            metadata_bytes_to_verify = json.dumps({
                "file_path": self.dummy_image_path.name,
                "file_hash": BLUE_IMG_SHA256,
                "hash_algorithm": "sha256",
                "created_at": MOCK_DATETIME.isoformat()
            }, sort_keys=True).encode("utf-8")

            mock_tst_info_obj = {
                "genTime": MOCK_DATETIME,
                "messageImprint": {
                    "hashAlgorithm": {"algorithm": "2.16.840.1.101.3.4.2.1"}, # sha-256 OID
                    "hashedMessage": hashlib.sha256(metadata_bytes_to_verify).digest()
                }
            }
            mock_get_tst_info.return_value = mock_tst_info_obj
            
            # Act
            verify_result = self.runner.invoke(
                vault_app,
                [
                    "verify-receipt",
                    str(self.receipt_path),
                    "--key",
                    str(self.pub_key_path),
                    "--file",
                    str(self.dummy_image_path),
                ],
            )
            
            # Assert verification
            self.assertEqual(verify_result.exit_code, 0)
            self.assertIn("File Hash: VERIFIED", verify_result.stdout)
            self.assertIn("Signature: VERIFIED", verify_result.stdout)
            self.assertIn("Timestamp: VERIFIED", verify_result.stdout)
            self.assertIn(f"Trusted Time: {MOCK_DATETIME}", verify_result.stdout)

    # --- Test 4: Export Derivative (NEW TEST) ---

    @patch("chimera_intel.core.forensic_vault.datetime")
    @patch("chimera_intel.core.forensic_vault._get_timestamp_token")
    def test_cli_export_derivative(self, mock_get_timestamp, mock_datetime):
        """Tests the new 'export-derivative' CLI command."""
        # Arrange
        mock_datetime.now.return_value = MOCK_DATETIME
        mock_get_timestamp.return_value = (MOCK_TS_RESPONSE_BYTES, MOCK_DATETIME)

        exported_path = self.test_dir / "exported_image.jpg"
        result_receipt_path = self.test_dir / "exported_image.jpg.receipt.json"

        # Act
        result = self.runner.invoke(
            vault_app,
            [
                "export-derivative",
                str(self.dummy_image_path),  # The "master" PNG
                "--key",
                str(self.priv_key_path),
                "--format",
                "jpg",
                "--output",
                str(exported_path),
                "--tsa-url",
                MOCK_TSA_URL,
            ],
        )

        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(exported_path.exists())
        self.assertTrue(result_receipt_path.exists())
        
        # Check hashes in stdout
        self.assertIn(f"Original Hash (SHA256): {BLUE_IMG_SHA256}", result.stdout)
        
        # Load the new JPG and calculate its hash to verify
        exported_bytes = exported_path.read_bytes()
        exported_hash = hashlib.sha256(exported_bytes).hexdigest()
        self.assertIn(f"Exported Hash (SHA256): {exported_hash}", result.stdout)
        
        # Check the result receipt
        with open(result_receipt_path, "r") as f:
            receipt_data = json.load(f)
        
        self.assertEqual(receipt_data["original_file"], self.dummy_image_path.name)
        self.assertEqual(receipt_data["exported_file"], exported_path.name)
        self.assertEqual(receipt_data["original_hash_sha256"], BLUE_IMG_SHA256)
        
        # Check that the receipt *inside* the result matches the exported file
        exported_receipt = receipt_data["exported_receipt"]
        self.assertEqual(exported_receipt["file_hash"], exported_hash)
        self.assertEqual(exported_receipt["file_path"], exported_path.name)
        self.assertEqual(exported_receipt["timestamp"], MOCK_DATETIME.isoformat())


if __name__ == "__main__":
    unittest.main()