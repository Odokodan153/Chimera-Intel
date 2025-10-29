import pytest
import httpx
import httpcore
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import Timeout, AsyncClient

# Import module and target function
from chimera_intel.core import http_client as http_client_module
from chimera_intel.core.http_client import get_async_http_client

# Mark module async
pytestmark = pytest.mark.asyncio


# --- Global network timeout patch ---
@pytest.fixture(autouse=True)
def mock_network_timeout():
    """Force deterministic NETWORK_TIMEOUT for all tests."""
    with patch("chimera_intel.core.http_client.NETWORK_TIMEOUT", 30.0) as mock_timeout:
        yield mock_timeout


# --- Async fixture to isolate global async client ---
@pytest.fixture
async def event_loop_client(mock_network_timeout):
    """
    Creates a new AsyncClient inside the current event loop,
    replaces the module’s global client for test isolation.
    """
    transport = httpx.AsyncHTTPTransport(retries=3)
    timeout_value = mock_network_timeout  # already patched value (30.0)

    client = AsyncClient(
        transport=transport,
        timeout=Timeout(timeout_value),
        headers={"User-Agent": "Chimera-Intel/6.0"},
    )

    with patch.object(http_client_module, "async_client", client):
        yield client

    await client.aclose()


# --- FIXED mock_pool_request fixture ---
@pytest.fixture
def mock_pool_request(event_loop_client):  # No 'async'
    """
    Patches the transport pool's 'request' method and yields an AsyncMock
    object so tests can directly configure `.return_value` and `.side_effect`.
    """
    mock_handle = AsyncMock()
    patcher = patch.object(
        event_loop_client._transport._pool,
        "request",
        mock_handle,
    )
    patcher.start()
    try:
        yield mock_handle
    finally:
        patcher.stop()


# --- Helper to simulate a pool response ---
def create_mock_pool_response(status_code, content: bytes):
    """Creates a fake (status, headers, stream, extensions) tuple."""
    headers = [(b"content-type", b"application/json")]

    async def async_iterator():
        yield content

    stream_mock = MagicMock()
    stream_mock.__aiter__ = async_iterator
    stream_mock.aclose = AsyncMock()

    return (status_code, headers, stream_mock, {})


# --- TESTS FOR GLOBAL CLIENT --- #

async def test_global_client_transport_success(mock_pool_request):
    """Test a successful HTTP request through the transport layer."""
    mock_pool_request.return_value = create_mock_pool_response(200, b'{"status": "ok"}')

    response = await http_client_module.async_client.request("GET", "https://example.com")

    assert response.status_code == 200
    await response.aread()
    assert response.json() == {"status": "ok"}
    assert mock_pool_request.call_count == 1

    called_request = mock_pool_request.call_args[0][0]
    assert called_request.method == b"GET"
    assert str(called_request.url) == "https://example.com/"


@pytest.mark.parametrize("status_code", [500, 502, 503, 504])
async def test_global_client_retry_on_server_error(mock_pool_request, status_code):
    """Ensure client retries on transient 5xx server errors."""
    mock_pool_request.return_value = create_mock_pool_response(status_code, b"Server Error")

    response = await http_client_module.async_client.request("GET", "https://example.com")

    assert response.status_code == status_code
    # 1 initial + 3 retries = 4 calls
    assert mock_pool_request.call_count == 4


async def test_global_client_retry_on_timeout(mock_pool_request):
    """Ensure retries occur on read timeouts."""
    mock_pool_request.side_effect = httpcore.ReadTimeout("Timeout")

    with pytest.raises(httpx.TimeoutException):
        await http_client_module.async_client.request("GET", "https://example.com")

    # Should retry 3 times + initial
    assert mock_pool_request.call_count == 4


async def test_global_client_no_retry_on_client_error(mock_pool_request):
    """Ensure 4xx errors do not trigger retries."""
    mock_pool_request.return_value = create_mock_pool_response(404, b"Not Found")

    response = await http_client_module.async_client.request("GET", "https://example.com")

    assert response.status_code == 404
    assert mock_pool_request.call_count == 1


# --- TESTS FOR get_async_http_client CONTEXT MANAGER --- #

@patch("chimera_intel.core.http_client.AsyncClient")
@patch("chimera_intel.core.http_client.httpx.AsyncHTTPTransport")
async def test_get_client_no_proxy(mock_transport_class, mock_client_class, mock_network_timeout):
    """Ensure a client is created without proxies."""
    mock_transport_instance = MagicMock(name="TransportInstance")
    mock_transport_class.return_value = mock_transport_instance

    mock_client_instance = MagicMock(name="ClientInstance")
    mock_client_instance.aclose = AsyncMock()
    mock_client_class.return_value = mock_client_instance

    async with get_async_http_client() as client:
        assert client == mock_client_instance

    mock_transport_class.assert_called_once_with(retries=3)
    mock_client_class.assert_called_once()

    kwargs = mock_client_class.call_args.kwargs
    assert kwargs["transport"] == mock_transport_instance
    assert isinstance(kwargs["timeout"], Timeout)
    assert kwargs["timeout"].read == 30.0
    assert kwargs["headers"] == {"User-Agent": "Chimera-Intel/6.0"}

    mock_client_instance.aclose.assert_called_once()


@patch("chimera_intel.core.http_client.AsyncClient")
@patch("chimera_intel.core.http_client.httpx.AsyncHTTPTransport")
async def test_get_client_with_proxy(mock_transport_class, mock_client_class, mock_network_timeout):
    """Ensure client uses proxy when provided."""
    mock_transport_instance = MagicMock(name="ProxyTransportInstance")
    mock_transport_class.return_value = mock_transport_instance

    mock_client_instance = MagicMock(name="ProxyClientInstance")
    mock_client_instance.aclose = AsyncMock()
    mock_client_class.return_value = mock_client_instance

    proxy_config = {"http": "http://user:pass@10.10.1.10:3128"}

    async with get_async_http_client(proxies=proxy_config) as client:
        assert client == mock_client_instance

    mock_transport_class.assert_called_once_with(
        retries=3, proxy="http://user:pass@10.10.1.10:3128"
    )

    mock_client_class.assert_called_once()
    kwargs = mock_client_class.call_args.kwargs
    assert kwargs["transport"] == mock_transport_instance
    assert isinstance(kwargs["timeout"], Timeout)
    assert kwargs["timeout"].read == 30.0
    assert kwargs["headers"] == {"User-Agent": "Chimera-Intel/6.0"}

    mock_client_instance.aclose.assert_called_once()
