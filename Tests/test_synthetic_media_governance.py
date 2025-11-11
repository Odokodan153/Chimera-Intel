import pytest
import os
import io
from unittest.mock import patch, MagicMock

# Ensure PIL and Numpy are mocked if not installed, or import for real
try:
    from PIL import Image, ImageDraw, ImageFont, ImageFilter
    import numpy as np
    LIBS_INSTALLED = True
except ImportError:
    LIBS_INSTALLED = False
    Image = MagicMock()
    ImageDraw = MagicMock()
    ImageFont = MagicMock()
    ImageFilter = MagicMock()
    np = MagicMock()
    Image.open.return_value.__enter__.return_value = MagicMock()


# Module under test
from chimera_intel.core import synthetic_media_governance as smg

# --- Fixtures ---

@pytest.fixture
def clean_image_bytes() -> bytes:
    """Creates a dummy PNG with moderate noise."""
    if not LIBS_INSTALLED:
        return b"clean_image_with_noise"
        
    img = Image.new('RGB', (500, 500), color=(100, 100, 100))
    # Add some random noise
    pixels = np.array(img)
    noise = np.random.randint(-10, 10, pixels.shape, dtype='int16')
    pixels = np.clip(pixels.astype('int16') + noise, 0, 255).astype('uint8')
    noisy_img = Image.fromarray(pixels)
    
    b = io.BytesIO()
    noisy_img.save(b, format='PNG')
    return b.getvalue()

@pytest.fixture
def low_noise_image_bytes() -> bytes:
    """Creates an unnaturally smooth image (solid color)."""
    if not LIBS_INSTALLED:
        return b"low_noise_image"
        
    img = Image.new('RGB', (500, 500), color=(100, 100, 100))
    b = io.BytesIO()
    img.save(b, format='PNG')
    return b.getvalue()

@pytest.fixture
def watermarked_image_bytes(clean_image_bytes) -> bytes:
    """Creates a watermarked version of the clean image."""
    if not LIBS_INSTALLED:
        return b"watermarked_image_bytes"
    return smg.apply_visible_watermark(clean_image_bytes)


# --- Tests ---

@pytest.mark.skipif(not LIBS_INSTALLED, reason="Pillow (PIL) or Numpy not found.")
def test_apply_visible_watermark(clean_image_bytes):
    """Tests that watermarking function runs and returns modified bytes."""
    original_len = len(clean_image_bytes)
    watermarked_bytes = smg.apply_visible_watermark(clean_image_bytes)
    
    assert watermarked_bytes is not None
    assert len(watermarked_bytes) != original_len
    
    # Check that the watermark was applied by detecting it
    result = smg.detect_synthetic_artifacts(watermarked_bytes)
    assert result["is_synthetic"] is True
    assert result["watermark_tag"] == smg.WATERMARK_TAG

@pytest.mark.skipif(not LIBS_INSTALLED, reason="Pillow (PIL) or Numpy not found.")
def test_detect_artifacts_watermarked(watermarked_image_bytes):
    """Tests that the *detector* finds the watermark."""
    result = smg.detect_synthetic_artifacts(watermarked_image_bytes)
    
    assert result["is_synthetic"] is True
    assert result["confidence"] > 0.9
    assert result["watermark_tag"] == smg.WATERMARK_TAG
    assert result["method"] == "Luminance Patch Analysis"

@pytest.mark.skipif(not LIBS_INSTALLED, reason="Pillow (PIL) or Numpy not found.")
def test_detect_artifacts_low_noise(low_noise_image_bytes):
    """Tests detection of simulated low-noise artifact."""
    result = smg.detect_synthetic_artifacts(low_noise_image_bytes)
    
    assert result["is_synthetic"] is True
    assert result["confidence"] > 0.6
    assert result["watermark_tag"] is None
    assert result["method"] == "Laplacian Noise Variance"

@pytest.mark.skipif(not LIBS_INSTALLED, reason="Pillow (PIL) or Numpy not found.")
def test_detect_artifacts_clean(clean_image_bytes):
    """Tests detection on a 'clean' asset with normal noise."""
    result = smg.detect_synthetic_artifacts(clean_image_bytes)
    
    assert result["is_synthetic"] is False
    assert result["method"] == "All checks passed"

@patch('chimera_intel.core.synthetic_media_governance.save_scan_to_db')
def test_log_abuse_report(mock_save_scan):
    """Tests that an abuse report is correctly formatted and saved."""
    asset_id = "syn_asset_123"
    reporter_email = "test@user.com"
    reason_text = "This asset is harmful."
    
    report_id = smg.log_abuse_report(
        generated_asset_id=asset_id,
        reporter=reporter_email,
        reason=reason_text
    )
    
    assert report_id.startswith("abuse_")
    
    # Check that save_scan_to_db was called with correct args
    mock_save_scan.assert_called_once()
    call_args = mock_save_scan.call_args[1]
    
    assert call_args['target'] == asset_id
    assert call_args['module'] == "synthetic_abuse_log"
    assert call_args['scan_id'] == report_id