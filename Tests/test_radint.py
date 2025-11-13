# Tests/test_radint.py
"""
Tests for the RADINT (Radar Intelligence) Core Module.

These tests use mocked geospatial data (numpy arrays) and patch
the 'rasterio.open' function to test the algorithmic logic
of the RadintClient without real files.
"""

import pytest
import pytest_asyncio
import numpy as np
from unittest.mock import MagicMock, patch, __dict__ as mock_dict
from pathlib import Path
from shapely.geometry import Polygon

# Module under test
from chimera_intel.core.radint import RadintClient, SarChangeReport
from chimera_intel.core.schemas import Coordinates

# Mock rasterio CRS object
class MockCRS:
    def to_epsg(self):
        return 4326

@pytest.fixture
def radint_client():
    """Provides a RadintClient instance."""
    return RadintClient()

@pytest.fixture
def mock_rasterio_open():
    """
    Mocks 'rasterio.open' and 'rasterio.mask.mask'.
    This is a context manager that yields a mock.
    """
    mock_src = MagicMock()
    mock_src.crs = MockCRS()
    
    # We'll configure the return value of mask.mask inside each test
    mock_mask = MagicMock()
    
    # We patch 'rasterio.open' as a context manager
    mock_open = MagicMock(return_value=mock_src)
    
    # Patch the modules used inside radint.py
    with patch('chimera_intel.core.radint.rasterio.open', mock_open), \
         patch('chimera_intel.core.radint.rasterio.mask.mask', mock_mask):
        yield mock_open, mock_mask

@pytest.mark.asyncio
async def test_analyze_sar_imagery_change_detected(radint_client, mock_rasterio_open):
    """
    Tests successful detection of change when SSIM is below threshold.
    """
    mock_open, mock_mask = mock_rasterio_open
    
    # 1. Define mock image data
    # "Before" image (e.g., a simple gradient)
    before_data = np.array([np.linspace(0, 255, 100) for _ in range(100)], dtype=np.uint8)
    # "After" image (a very different image)
    after_data = np.array([np.linspace(255, 0, 100) for _ in range(100)], dtype=np.uint8)
    
    # Configure mask.mask to return these arrays
    mock_mask.side_effect = [
        (np.array([before_data]), MagicMock()), # First call (before)
        (np.array([after_data]), MagicMock())   # Second call (after)
    ]
    
    # 2. Define AOI
    aoi = [
        Coordinates(lat=0, lon=0), Coordinates(lat=1, lon=0),
        Coordinates(lat=1, lon=1), Coordinates(lat=0, lon=1)
    ]
    
    # 3. Run analysis
    report = await radint_client.analyze_sar_imagery(
        before_image_path=Path("fake/before.tif"),
        after_image_path=Path("fake/after.tif"),
        aoi_coords=aoi
    )
    
    # 4. Assert results
    assert report.change_detected is True
    assert "Significant structural change" in report.change_summary
    assert "SSIM score:" in report.detailed_description
    # SSIM for these two arrays will be very low (approx -1.0)
    assert float(report.detailed_description.split(':')[1].split('.')[0]) < 0

@pytest.mark.asyncio
async def test_analyze_sar_imagery_no_change(radint_client, mock_rasterio_open):
    """
    Tests successful non-detection of change when SSIM is above threshold.
    """
    mock_open, mock_mask = mock_rasterio_open
    
    # 1. Define mock image data
    # "Before" and "After" images are identical
    image_data = np.array([np.linspace(0, 255, 100) for _ in range(100)], dtype=np.uint8)
    
    mock_mask.side_effect = [
        (np.array([image_data]), MagicMock()),
        (np.array([image_data]), MagicMock())
    ]
    
    # 2. Define AOI
    aoi = [Coordinates(lat=0, lon=0), Coordinates(lat=1, lon=0), Coordinates(lat=1, lon=1)]
    
    # 3. Run analysis
    report = await radint_client.analyze_sar_imagery(
        before_image_path=Path("fake/before.tif"),
        after_image_path=Path("fake/after.tif"),
        aoi_coords=aoi
    )
    
    # 4. Assert results
    assert report.change_detected is False
    assert "No significant structural change" in report.change_summary
    assert "SSIM score: 1.0000" in report.detailed_description

@pytest.mark.asyncio
async def test_analyze_sar_imagery_file_not_found(radint_client, mock_rasterio_open):
    """Tests handling of a FileNotFoundError."""
    mock_open, mock_mask = mock_rasterio_open
    
    # Configure rasterio.open to raise an error
    mock_open.side_effect = FileNotFoundError("File not found")
    
    aoi = [Coordinates(lat=0, lon=0), Coordinates(lat=1, lon=0), Coordinates(lat=1, lon=1)]
    
    report = await radint_client.analyze_sar_imagery(
        before_image_path=Path("non_existent.tif"),
        after_image_path=Path("non_existent_after.tif"),
        aoi_coords=aoi
    )
    
    assert report.change_detected is False
    assert "File not found" in report.detailed_description

@pytest.mark.asyncio
async def test_analyze_sar_imagery_no_overlap(radint_client, mock_rasterio_open):
    """Tests when the AOI does not overlap the image."""
    mock_open, mock_mask = mock_rasterio_open
    
    # Configure mask.mask to raise a ValueError (which it does on no overlap)
    mock_mask.side_effect = ValueError("Input shapes do not overlap")
    
    aoi = [Coordinates(lat=0, lon=0), Coordinates(lat=1, lon=0), Coordinates(lat=1, lon=1)]
    
    report = await radint_client.analyze_sar_imagery(
        before_image_path=Path("fake/image1.tif"),
        after_image_path=Path("fake/image2.tif"),
        aoi_coords=aoi
    )
    
    assert report.change_detected is False
    assert "AOI may not overlap" in report.detailed_description

@pytest.mark.asyncio
async def test_analyze_sar_imagery_mismatched_shape(radint_client, mock_rasterio_open):
    """Tests logic to resize images when shapes are mismatched."""
    mock_open, mock_mask = mock_rasterio_open

    # 1. Define mock image data
    before_data = np.array([np.linspace(0, 255, 100) for _ in range(100)], dtype=np.uint8)
    # "After" image is a different shape
    after_data = np.array([np.linspace(0, 255, 50) for _ in range(50)], dtype=np.uint8)
    
    mock_mask.side_effect = [
        (np.array([before_data]), MagicMock()),
        (np.array([after_data]), MagicMock())
    ]
    
    aoi = [Coordinates(lat=0, lon=0), Coordinates(lat=1, lon=0), Coordinates(lat=1, lon=1)]
    
    # 3. Run analysis
    # We patch skimage.transform.resize to verify it's called
    with patch('chimera_intel.core.radint.resize') as mock_resize:
        # Configure resize to return a compatible array
        mock_resize.return_value = before_data # Return an identical, resized array
        
        report = await radint_client.analyze_sar_imagery(
            before_image_path=Path("fake/before.tif"),
            after_image_path=Path("fake/after.tif"),
            aoi_coords=aoi
        )
    
    # 4. Assert results
    mock_resize.assert_called_once() # Verify resizing logic was triggered
    assert report.change_detected is False # Because we returned identical data
    assert "SSIM score: 1.0000" in report.detailed_description