import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
import json
# Mock core instances
mock_event_mesh = MagicMock(spec=EventMesh)
mock_event_mesh.publish = AsyncMock()
mock_event_mesh.subscribe = AsyncMock()

mock_config = MagicMock(spec=ConfigLoader)
mock_config.get_api_key = MagicMock(return_value="test_api_key")
mock_config.get = MagicMock(side_effect=lambda key, default=None: {
    "feed_mesh.alert_domains": ["my-company.com", "my-app.io"]
}.get(key, default))

modules = {
    "src.chimera_intel.core.event_mesh": MagicMock(event_mesh=mock_event_mesh),
    "src.chimera_intel.core.config_loader": MagicMock(ConfigLoader=lambda: mock_config),
    "src.chimera_intel.core.logger_config": MagicMock(setup_logging=MagicMock()),
    "src.chimera_intel.core.utils": MagicMock(),
}

with patch.dict("sys.modules", modules):
    from src.chimera_intel.core.feed_mesh_integrations import FeedIntegrator, RealTimeAlerter
    from src.chimera_intel.core.event_mesh import EventMesh
    from src.chimera_intel.core.config_loader import ConfigLoader


@pytest.fixture
def feed_integrator():
    mock_event_mesh.reset_mock()
    mock_config.reset_mock()
    return FeedIntegrator(mock_event_mesh, mock_config)

@pytest.fixture
def real_time_alerter():
    mock_event_mesh.reset_mock()
    mock_config.reset_mock()
    mock_config.get.side_effect = lambda key, default=None: {
        "feed_mesh.alert_domains": ["my-company.com", "my-app.io"]
    }.get(key, default)
    return RealTimeAlerter(mock_event_mesh, mock_config)

@pytest.mark.asyncio
async def test_certstream_alerter(real_time_alerter):
    """
    Tests that the alerter correctly identifies a monitored domain from a Certstream event.
    """
    await real_time_alerter.start_monitoring()
    
    certstream_callback = None
    for call in mock_event_mesh.subscribe.call_args_list:
        if call[0][0] == "certstream_feed":
            certstream_callback = call[0][1]
            break
            
    assert certstream_callback is not None, "Alerter did not subscribe to 'certstream_feed'"

    cert_event = {
        "message_type": "certificate_update",
        "data": {"leaf_cert": {"subject": {"CN": "login.my-company.com"}}}
    }
    await certstream_callback(cert_event)
    
    mock_event_mesh.publish.assert_called_once_with(
        "alerts",
        pytest.match(lambda x: 
            x["type"] == "certstream_alert" and 
            x["domain"] == "login.my-company.com"
        )
    )

@pytest.mark.asyncio
async def test_malware_feed_alerter(real_time_alerter):
    """
    Tests that the alerter correctly identifies a monitored domain from a malware feed event.
    """
    await real_time_alerter.start_monitoring()

    malware_callback = None
    for call in mock_event_mesh.subscribe.call_args_list:
        if call[0][0] == "malware_feed":
            malware_callback = call[0][1]
            break
            
    assert malware_callback is not None, "Alerter did not subscribe to 'malware_feed'"

    malware_event_matching = {
        "source": "urlhaus",
        "url": "http://phishing.my-app.io/login.php",
        "threat": "phishing",
    }
    
    await malware_callback(malware_event_matching)
    
    mock_event_mesh.publish.assert_called_once_with(
        "alerts",
        pytest.match(lambda x:
            x["type"] == "malware_alert" and
            x["domain"] == "phishing.my-app.io"
        )
    )

@pytest.mark.asyncio
@patch('src.chimera_intel.core.feed_mesh_integrations.websockets.connect')
async def test_certstream_integrator(mock_ws_connect, feed_integrator):
    """
    Tests that the Certstream integrator connects and publishes messages to the event mesh.
    """
    mock_websocket = AsyncMock()
    mock_websocket.__aenter__.return_value.recv.side_effect = [
        json.dumps({"message_type": "heartbeat"}),
        json.dumps({
            "message_type": "certificate_update",
            "data": {"leaf_cert": {"subject": {"CN": "test.com"}}}
        }),
        Exception("Stop loop") # To stop the infinite loop
    ]
    mock_ws_connect.return_value = mock_websocket

    task = asyncio.create_task(feed_integrator._start_certstream_stream())
    await asyncio.sleep(0.01) # Give the task time to run
    task.cancel()
    
    mock_ws_connect.assert_called_with("wss://certstream.calidog.io/")
    
    mock_event_mesh.publish.assert_called_once_with(
        "certstream_feed",
        pytest.match(lambda x: x["message_type"] == "certificate_update")
    )