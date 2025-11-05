"""
Tests for the Production IMINT Ingestion Pipeline.

This test module mocks all external clients and heavy ML models:
- requests.get
- boto3.client (s3_client)
- easyocr.Reader (ocr_reader)
- cv2.CascadeClassifier (face_cascade)
- transformers.CLIPModel & CLIPProcessor (clip_model, clip_processor)
- google.cloud.vision.ImageAnnotatorClient (gcp_vision_client)
- googleapiclient.discovery.build (Google Search)
- tweepy.Client (Twitter/X)
- chimera_intel.core.database.get_db_connection
- chimera_intel.core.graph_db.get_graph_driver
"""

import pytest
import os
import requests
import numpy as np
import torch
from unittest.mock import patch, MagicMock

# Ensure the src directory is in the Python path for testing
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from chimera_intel.core import imint_ingestion
from chimera_intel.core.schemas import ImageSourceType, IngestedImageRecord, ExifData, ImageFeatures, ImageEnrichment
from pydantic import HttpUrl
from datetime import datetime
from botocore.exceptions import NoCredentialsError, ClientError

# --- Fixtures ---

@pytest.fixture(scope="module")
def sample_image_bytes() -> bytes:
    """Returns mock JPEG image bytes (1x1 black pixel)."""
    return (
        b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00\x03\x02\x02\x02\x02\x02'
        b'\x03\x02\x02\x02\x03\x03\x03\x03\x04\x06\x04\x04\x04\x04\x04\x08\x06\x06\x05\x06\t\x08\n\n\t\x08\t\t\n\x0c\x0f'
        b'\x0c\n\x0b\x0e\x0b\t\t\r\x11\r\x0e\x0f\x10\x10\x11\x10\n\x0c\x12\x13\x12\x10\x13\x0f\x10\x10\x10\xff\xc9\x00\x0b'
        b'\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xcc\x00\x06\x00\x01\x00\x00\xff\xda\x00\x08\x01\x01\x00\x00\x00\x00'
        b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x80\x01\xff\xd9'
    )

@pytest.fixture
def mock_requests_get(sample_image_bytes):
    """Mocks requests.get to return sample image bytes."""
    mock_response = MagicMock()
    mock_response.content = sample_image_bytes
    mock_response.headers = {"Content-Type": "image/jpeg"}
    mock_response.raise_for_status = MagicMock()
    
    with patch("requests.get", return_value=mock_response) as mock_get:
        yield mock_get

@pytest.fixture(autouse=True)
def mock_all_clients():
    """Mocks all global clients (S3, ML, CV, DBs) for all tests."""
    
    # Mock S3 Client
    mock_s3 = MagicMock()
    mock_s3.put_object = MagicMock()
    mock_s3.head_bucket = MagicMock() # For the startup check
    
    # Mock EasyOCR
    mock_ocr = MagicMock()
    mock_ocr.readtext.return_value = [("Mocked OCR Text",)]
    
    # Mock OpenCV
    mock_cv = MagicMock()
    mock_cv.detectMultiScale.return_value = np.array([[10, 20, 30, 40]]) # One face
    
    # Mock Google Vision
    mock_gcp_vision = MagicMock()
    mock_gcp_vision.logo_detection.return_value = MagicMock(logo_annotations=[MagicMock(description="Google")])
    mock_gcp_vision.web_detection.return_value = MagicMock(web_detection=MagicMock(pages_with_matching_images=[MagicMock(url="https://google.com/match", score=0.9)]))
    
    # Mock CLIP Model
    mock_clip_model = MagicMock()
    mock_clip_model.get_image_features.return_value = torch.tensor(np.random.rand(1, 512))
    
    # Mock CLIP Processor
    mock_clip_processor = MagicMock()
    mock_clip_processor.return_value = {"pixel_values": torch.tensor(np.random.rand(1, 3, 224, 224))}
    
    # Mock Google Search API
    mock_google_search_service = MagicMock()
    mock_google_search_service.cse().list().execute.return_value = {
        "items": [
            {
                "link": "https://example.com/img.jpg",
                "image": {"contextLink": "https://example.com/page.html"},
                "title": "Example Image"
            }
        ]
    }
    mock_google_build = MagicMock(return_value=mock_google_search_service)
    
    # Mock Tweepy
    mock_tweepy_client = MagicMock()
    mock_tweet = MagicMock(id="123", text="Test tweet", created_at=datetime.utcnow(), attachments={"media_keys": ["m1"]})
    mock_media = MagicMock(media_key="m1", type="photo", url="https://pbs.twimg.com/img.jpg")
    mock_user = MagicMock(id="u1", username="testuser")
    mock_tweepy_client.search_recent_tweets.return_value = MagicMock(
        data=[mock_tweet],
        includes={"media": [mock_media], "users": [mock_user]}
    )
    
    # Mock DBs
    mock_pg_cursor = MagicMock()
    mock_pg_cursor.fetchone.return_value = ["new-mock-uuid-1234"] # Return the new ID
    mock_pg_conn = MagicMock()
    mock_pg_conn.cursor.return_value = mock_pg_cursor
    mock_db_conn = MagicMock(return_value=mock_pg_conn)
    
    mock_neo_session = MagicMock()
    mock_neo_session.run = MagicMock()
    mock_neo_driver = MagicMock()
    mock_neo_driver.session.return_value = mock_neo_session
    mock_graph_driver = MagicMock(return_value=mock_neo_driver)

    with patch("chimera_intel.core.imint_ingestion.s3_client", mock_s3), \
         patch("chimera_intel.core.imint_ingestion.ocr_reader", mock_ocr), \
         patch("chimera_intel.core.imint_ingestion.face_cascade", mock_cv), \
         patch("chimera_intel.core.imint_ingestion.gcp_vision_client", mock_gcp_vision), \
         patch("chimera_intel.core.imint_ingestion.clip_model", mock_clip_model), \
         patch("chimera_intel.core.imint_ingestion.clip_processor", mock_clip_processor), \
         patch("chimera_intel.core.imint_ingestion.google_api_build", mock_google_build), \
         patch("chimera_intel.core.imint_ingestion.TweepyClient", return_value=mock_tweepy_client), \
         patch("chimera_intel.core.imint_ingestion.get_db_connection", mock_db_conn), \
         patch("chimera_intel.core.imint_ingestion.get_graph_driver", mock_graph_driver):
        
        yield {
            "s3": mock_s3,
            "ocr": mock_ocr,
            "cv": mock_cv,
            "gcp_vision": mock_gcp_vision,
            "clip_model": mock_clip_model,
            "google_search": mock_google_build,
            "tweepy": mock_tweepy_client,
            "pg_conn": mock_db_conn,
            "neo_driver": mock_graph_driver
        }


# --- Tests ---

def test_fetch_raw_image_success(mock_requests_get, sample_image_bytes):
    url = HttpUrl("https://example.com/image.jpg")
    img_bytes, content_type = imint_ingestion.fetch_raw_image(url)
    mock_requests_get.assert_called_once()
    assert img_bytes == sample_image_bytes
    assert content_type == "image/jpeg"

def test_normalize_and_hash(sample_image_bytes):
    sha256, res, size, mime, exif = imint_ingestion.normalize_and_hash(
        sample_image_bytes, "image/jpeg"
    )
    assert sha256 == "03dd0ee3d82a6111a43ef505051a388915d61e38aff5634e70d7a0410d88b6f5"
    assert res == "1x1"
    assert size == len(sample_image_bytes)
    assert mime == "image/jpeg"
    assert isinstance(exif, ExifData)

def test_store_raw_image(mock_all_clients, sample_image_bytes):
    s3_key = imint_ingestion.store_raw_image(
        sample_image_bytes, "test_hash", "image/jpeg"
    )
    assert s3_key == "imint/raw/test_hash.jpg"
    mock_all_clients["s3"].put_object.assert_called_once_with(
        Bucket=os.environ.get("S3_BUCKET", "chimera-intel-imint-storage"),
        Key="imint/raw/test_hash.jpg",
        Body=sample_image_bytes,
        ContentType="image/jpeg"
    )

def test_index_features(mock_all_clients, sample_image_bytes):
    features = imint_ingestion.index_features(sample_image_bytes)
    assert isinstance(features, ImageFeatures)
    assert features.perceptual_hash == "810ff80f07c1e0ff" # Real hash
    assert features.difference_hash == "0000000000000000" # Real hash
    assert features.embedding_model_name == "openai/clip-vit-base-patch32" # From mock
    assert features.embedding_vector_shape == "(1, 512)" # From mock
    mock_all_clients["clip_model"].get_image_features.assert_called_once()

def test_enrich_image(mock_all_clients, sample_image_bytes):
    exif_data = ExifData(Make="Test")
    enrichment = imint_ingestion.enrich_image(sample_image_bytes, exif_data)
    
    assert isinstance(enrichment, ImageEnrichment)
    # Check OCR
    mock_all_clients["ocr"].readtext.assert_called_once_with(
        sample_image_bytes, detail=0, paragraph=True
    )
    assert enrichment.ocr_text == "Mocked OCR Text"
    
    # Check CV
    mock_all_clients["cv"].detectMultiScale.assert_called_once()
    assert enrichment.detected_faces_count == 1
    assert enrichment.face_locations[0]["box"] == [10, 20, 30, 40]
    
    # Check Logo
    mock_all_clients["gcp_vision"].logo_detection.assert_called_once()
    assert enrichment.detected_logos == ["Google"]
    
    assert enrichment.exif_data == exif_data

def test_run_full_ingestion_pipeline(mock_requests_get, mock_all_clients, sample_image_bytes):
    """Tests the full end-to-end orchestration with all mocks."""
    
    url = HttpUrl("https://example.com/image.jpg")
    ctx_url = HttpUrl("https://example.com/page.html")
    
    record = imint_ingestion.run_full_ingestion(
        source_url=url,
        source_type=ImageSourceType.NEWS,
        source_context_url=ctx_url
    )
    
    known_hash = "03dd0ee3d82a6111a43ef505051a388915d61e38aff5634e70d7a0410d88b6f5"
    
    # 1. Fetch
    mock_requests_get.assert_called_with(str(url), headers=pytest.ANY, timeout=10, stream=True)
    # 2. Normalize
    assert record.sha256_hash == known_hash
    # 3. Store
    mock_all_clients["s3"].put_object.assert_called_once()
    # 4. Index
    assert record.features.perceptual_hash == "810ff80f07c1e0ff"
    assert record.features.embedding_vector_shape == "(1, 512)"
    # 5. Enrich
    assert record.enrichment.ocr_text == "Mocked OCR Text"
    assert record.enrichment.detected_faces_count == 1
    assert record.enrichment.detected_logos == ["Google"]
    # 6. Link to ARG
    assert mock_all_clients["neo_driver"]().session().run.call_count > 0
    # 7. Store Metadata
    assert mock_all_clients["pg_conn"]().cursor().execute.call_count > 0
    
    # Final record
    assert record.error is None
    assert record.id == "new-mock-uuid-1234"
    assert record.arg_node_id == f"Image:{known_hash}"

def test_fetch_images_from_google_api(mock_all_clients):
    results = imint_ingestion.fetch_images_from_google("test", 1)
    mock_all_clients["google_search"].assert_called_once()
    assert len(results) == 1
    assert results[0]["source_url"] == "https://example.com/img.jpg"
    assert results[0]["source_context_url"] == "https://example.com/page.html"
    assert results[0]["source_type"] == ImageSourceType.GOOGLE_IMAGES

def test_fetch_images_from_twitter_api(mock_all_clients):
    results = imint_ingestion.fetch_images_from_twitter("test", 1)
    mock_all_clients["tweepy"](
        os.environ.get("TWITTER_BEARER_TOKEN")
    ).search_recent_tweets.assert_called_once()
    assert len(results) == 1
    assert results[0]["source_url"] == "https://pbs.twimg.com/img.jpg"
    assert results[0]["source_context_url"] == "https://x.com/testuser/status/123"
    assert results[0]["source_type"] == ImageSourceType.TWITTER