# Tests/test_brand_protection_pipeline.py

import pytest
import pytest_asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from pydantic import HttpUrl
import datetime

# Module under test
from chimera_intel.core.brand_protection_pipeline import (
    BrandProtectionPipeline, 
    TriageTask, 
    BrandThreat
)

# Mock schemas from the provided schemas.py
from chimera_intel.core.schemas import (
    IngestedImageRecord,
    ManipulationDetectionResult,
    DeepfakeAnalysisResult,
    ImageSourceType
)

@pytest.fixture
def mock_db():
    """Fixture for a mocked Database."""
    db = MagicMock()
    db.save_triage_task = AsyncMock()
    db.get_triage_task = AsyncMock()
    db.update_triage_task = AsyncMock()
    db.get_tasks_by_status = AsyncMock()
    db.save_brand_threat = AsyncMock()
    return db

@pytest.fixture
def mock_media_record():
    """Mock IngestedImageRecord."""
    return IngestedImageRecord(
        id="img-123",
        source_url=HttpUrl("http://social.com/post/abc.jpg", scheme="http"),
        source_type=ImageSourceType.TWITTER,
        storage_key="s3://bucket/abc.jpg",
        sha256_hash="abc123hash"
    )

@pytest.fixture
def mock_detection_result():
    """Mock ManipulationDetectionResult that is a confirmed deepfake."""
    return ManipulationDetectionResult(
        deepfake_scan=DeepfakeAnalysisResult(
            file_path="s3://bucket/abc.jpg",
            is_deepfake=True,
            confidence=0.95,
            inconsistencies=["Facial artifacting"]
        )
    )

@pytest.fixture
def mock_alert_data():
    """Mock alert data from a monitor."""
    return {
        "url": "http://social.com/post/abc.jpg",
        "context_url": "http://social.com/post/abc",
        "source": "social.com",
        "source_type": "social",
        "provenance": {"source_type": "social", "author": "user123"}
    }

# Patch all external clients for the pipeline
@patch('chimera_intel.core.brand_protection_pipeline.SocialMediaMonitor', MagicMock())
@patch('chimera_intel.core.brand_protection_pipeline.DarkWebMonitor', MagicMock())
@patch('chimera_intel.core.brand_protection_pipeline.PageMonitor', MagicMock())
@patch('chimera_intel.core.brand_protection_pipeline.IMINT', MagicMock())
@patch('chimera_intel.core.brand_protection_pipeline.ImageForensicsPipeline', MagicMock())
@patch('chimera_intel.core.brand_protection_pipeline.DataIngestion', MagicMock())
@patch('chimera_intel.core.brand_protection_pipeline.SocialAnalyzer', MagicMock())
@pytest.fixture
def pipeline(mock_db):
    """Fixture for the pipeline with all clients mocked."""
    return BrandProtectionPipeline(db_session=mock_db)


@pytest.mark.asyncio
async def test_process_one_alert_to_triage(pipeline, mock_alert_data, mock_media_record, mock_detection_result):
    """
    Tests the ingestion pipeline from alert to triage queue.
    """
    # Setup mocks
    pipeline.data_ingestion.ingest_media = AsyncMock(return_value=mock_media_record)
    pipeline.detection_pipeline.analyze = AsyncMock(return_value=mock_detection_result)
    pipeline.triage_queue.put = AsyncMock()

    # Run the internal processing method
    await pipeline._process_one_alert(mock_alert_data)

    # Asserts
    pipeline.data_ingestion.ingest_media.assert_called_with(
        "http://social.com/post/abc.jpg",
        source_type="social",
        context_url="http://social.com/post/abc"
    )
    pipeline.detection_pipeline.analyze.assert_called_with(mock_media_record.storage_key)
    pipeline.triage_queue.put.assert_called_with((mock_media_record, mock_detection_result, mock_alert_data))


@pytest.mark.asyncio
async def test_submit_triage_result_positive(pipeline, mock_db, mock_detection_result):
    """
    Tests the triage workflow for a confirmed positive.
    """
    mock_task_data = {
        "task_id": "triage-123",
        "media_url": "http://social.com/post/abc.jpg",
        "source": "social.com",
        "provenance_data": {"source_type": "social"},
        "detection_result": mock_detection_result.dict(),
        "status": "pending"
    }
    mock_db.get_triage_task.return_value = mock_task_data
    pipeline.scoring_queue.put = AsyncMock()

    result = await pipeline.submit_triage_result("triage-123", is_positive=True, notes="Confirmed deepfake.")

    assert result['status'] == 'confirmed_positive'
    
    # Check that the task was updated in the DB
    updated_task_data = pipeline.db.update_triage_task.call_args[0][1]
    assert updated_task_data['status'] == 'confirmed_positive'
    assert updated_task_data['analyst_notes'] == 'Confirmed deepfake.'
    
    # Check that it was sent to the scoring queue
    pipeline.scoring_queue.put.assert_called_once()


@pytest.mark.asyncio
async def test_threat_scoring_social_high_reach(pipeline, mock_db, mock_detection_result):
    """
    Tests the threat scoring logic for a high-reach social media post.
    """
    # Confirmed positive task from triage
    task = TriageTask(
        task_id="triage-789",
        media_url="http://social.com/post/xyz",
        source="social.com",
        provenance_data={"source_type": "social", "author": "influencer"},
        detection_result=mock_detection_result, # confidence 0.95
        status="confirmed_positive"
    )

    # Mock SocialAnalyzer to return high-reach metrics
    pipeline.social_analyzer.get_profile_metrics_by_post = AsyncMock(return_value={
        "followers": 2_000_000,  # Score: 1.0
        "repost_rate": 0.08      # Score: 1.0
    })

    # Run the internal scoring method
    await pipeline._process_one_scoring_task(task)

    # Assert that a threat was saved
    pipeline.db.save_brand_threat.assert_called_once()
    
    # Check the scoring math
    saved_threat = BrandThreat(**pipeline.db.save_brand_threat.call_args[0][0])
    
    assert saved_threat.reach_score == 1.0
    assert saved_threat.detection_score == 0.95
    
    # final_score = (1.0 * 0.6) + (0.95 * 0.4) = 0.6 + 0.38 = 0.98
    assert saved_threat.final_threat_score == 0.98