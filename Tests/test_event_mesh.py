"""
Tests for the EventMesh module.
"""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

from chimera_intel.core.event_mesh import EventMesh, RSSFeedHandler, FeedConfig
from chimera_intel.core.correlation_engine import CorrelationEngine
from chimera_intel.core.schemas import Event

# A sample RSS feed response
SAMPLE_RSS_XML = """
<rss version="2.0">
<channel>
  <title>Sample Feed</title>
  <item>
    <title>Test Event 1</title>
    <link>http://example.com/1</link>
    <guid isPermaLink="false">http://example.com/1</guid>
    <pubDate>Sun, 02 Nov 2025 20:00:00 +0000</pubDate>
    <description>This is the first test event.</description>
  </item>
  <item>
    <title>Test Event 2</title>
    <link>http://example.com/2</link>
    <guid isPermaLink="false">http://example.com/2</guid>
    <pubDate>Sun, 02 Nov 2025 21:00:00 +0000</pubDate>
    <description>This is the second test event.</description>
  </item>
</channel>
</rss>
"""

# Sample feed configuration
MOCK_FEED_CONFIG = {
    "name": "test_rss_feed",
    "type": "rss",
    "url": "http://mock.feed/rss",
    "interval_seconds": 1, # Short interval for testing
    "event_type": "rss_signal",
}


@pytest.fixture
def mock_correlation_engine():
    """Fixture for a mock CorrelationEngine."""
    engine = MagicMock(spec=CorrelationEngine)
    engine.process_event = MagicMock()
    return engine


@pytest.fixture
def mock_async_client():
    """Fixture to mock the async_client."""
    # Create a mock response object
    mock_response = MagicMock()
    mock_response.text = SAMPLE_RSS_XML
    mock_response.raise_for_status = MagicMock()

    # Patch 'chimera_intel.core.event_mesh.async_client'
    with patch(
        "chimera_intel.core.event_mesh.async_client", new_callable=AsyncMock
    ) as mock_client:
        mock_client.get = AsyncMock(return_value=mock_response)
        yield mock_client


@pytest.mark.asyncio
async def test_rss_feed_handler_fetch(mock_async_client):
    """Tests that the RSS handler correctly parses a feed."""
    handler = RSSFeedHandler()
    config = FeedConfig.model_validate(MOCK_FEED_CONFIG)
    
    events = await handler.fetch(config)
    
    assert len(events) == 2
    assert events[0].event_type == "rss_signal"
    assert events[0].source == "test_rss_feed"
    assert events[0].details["title"] == "Test Event 1"
    assert events[1].details["title"] == "Test Event 2"
    assert events[0].id is not None
    assert events[0].id != events[1].id


@pytest.mark.asyncio
@patch("asyncio.sleep", new_callable=AsyncMock) # Patch sleep to speed up test
async def test_event_mesh_start_and_process(
    mock_sleep, mock_async_client, mock_correlation_engine
):
    """
    Tests the main EventMesh loop for processing and deduplication.
    """
    mesh = EventMesh(
        correlation_engine=mock_correlation_engine,
        feed_configs=[MOCK_FEED_CONFIG],
    )

    # We run the task, let it process once, then cancel it.
    mesh_task = asyncio.create_task(mesh.start())
    
    # Give the task time to run its loop once
    await asyncio.sleep(0.1) 
    
    # --- First run ---
    # It should have processed 2 new events
    assert mock_correlation_engine.process_event.call_count == 2
    call_args_1 = mock_correlation_engine.process_event.call_args_list[0].args[0]
    call_args_2 = mock_correlation_engine.process_event.call_args_list[1].args[0]
    
    assert isinstance(call_args_1, Event)
    assert call_args_1.details["title"] == "Test Event 1"
    assert call_args_2.details["title"] == "Test Event 2"
    assert len(mesh.seen_event_ids) == 2

    # Clear the mock for the next check
    mock_correlation_engine.process_event.reset_mock()

    # --- Second run (Deduplication) ---
    # Let the loop run again
    await asyncio.sleep(0.1) 
    
    # This time, it should NOT process any events, as they are duplicates
    assert mock_correlation_engine.process_event.call_count == 0
    assert len(mesh.seen_event_ids) == 2
    
    # Stop the mesh
    mesh.stop()
    mesh_task.cancel()
    try:
        await mesh_task
    except asyncio.CancelledError:
        pass # Expected


@pytest.mark.asyncio
async def test_event_mesh_no_handler(mock_correlation_engine):
    """Tests that the mesh logs a warning for an unknown feed type."""
    bad_config = MOCK_FEED_CONFIG.copy()
    bad_config["type"] = "unknown_type"
    
    mesh = EventMesh(
        correlation_engine=mock_correlation_engine,
        feed_configs=[bad_config],
    )
    
    mesh_task = asyncio.create_task(mesh.start())
    await asyncio.sleep(0.1) # Let it run once
    
    # It should not have called the engine
    assert mock_correlation_engine.process_event.call_count == 0

    mesh.stop()
    mesh_task.cancel()
    try:
        await mesh_task
    except asyncio.CancelledError:
        pass