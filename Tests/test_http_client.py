import pytest
import httpx
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import Timeout

# Import the actual objects from the source file
from src.chimera_intel.core.http_client import async_client, get_async_http_client

# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def mock_network_timeout():
    """
    Mocks the global NETWORK_TIMEOUT constant *where it is used*
    to ensure a predictable value for tests.
    """
    # The global async_client is created at import time, so we can't
    # patch its timeout easily. But we can patch the constant
    # for the get_async_http_client function which reads it dynamically.
    with patch("src.chimera_intel.core.http_client.NETWORK_TIMEOUT", 30.0) as mock_timeout:
        yield mock_timeout


@pytest.fixture
def mock_pool_request():
    """
    Mocks the underlying pool request method, which is called
    by the transport's handle_async_request. This allows the
    transport's *own* retry logic to execute.
    """
    with patch(
        "httpx._async.connection_pool.AsyncConnectionPool.handle_async_request",
        new_callable=AsyncMock,
    ) as mock_handle:
        yield mock_handle


# --- Helper to create a mock pool response ---
def create_mock_pool_response(status_code, content):
    """Creates a mock (status, headers, stream, extensions) tuple."""
    headers = [(b"content-type", b"application/json")]
    stream = AsyncMock(spec=httpx.AsyncByteStream)
    stream.read = AsyncMock(return_value=content)
    stream.aclose = AsyncMock()
    return (status_code, headers, stream, {})


# --- Tests for global async_client ---
# These tests check the behavior of the global client, specifically
# its retry logic which is configured via its transport.

async def test_global_client_transport_success(mock_pool_request):
    """Test a successful request via the transport."""
    mock_pool_request.return_value = create_mock_pool_response(
        200, b'{"status": "ok"}'
    )

    response = await async_client.request("GET", "https://example.com")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert mock_pool_request.call_count == 1

    # Check args of the pool call
    called_request = mock_pool_request.call_args[0][0]
    assert called_request.method == b"GET"
    assert str(called_request.url) == "https://example.com/"


@pytest.mark.parametrize(
    "status_code",
    [
        (500),
        (502),
        (503),
        (504),
    ],
)
async def test_global_client_retry_on_server_error(mock_pool_request, status_code):
    """Test that the client retries on 5xx server errors."""
    mock_pool_request.return_value = create_mock_pool_response(
        status_code, b"Server Error"
    )

    # The global transport is configured with retries=3.
    # This means 1 initial call + 3 retries = 4 attempts.
    # The client itself doesn't raise, it just returns the final
    # error response after retries are exhausted.
    response = await async_client.request("GET", "https://example.com")

    # The final response should be the error
    assert response.status_code == status_code
    # The pool's handle_async_request should be called 4 times
    assert mock_pool_request.call_count == 4


async def test_global_client_retry_on_timeout(mock_pool_request):
    """Test that the client retries on httpx.TimeoutException."""
    # The transport's underlying call will raise TimeoutException
    mock_pool_request.side_effect = httpx.TimeoutException("Timeout")

    with pytest.raises(httpx.TimeoutException):
        await async_client.request("GET", "https://example.com")

    # Should be called 1 initial + 3 retries = 4 times
    assert mock_pool_request.call_count == 4


async def test_global_client_no_retry_on_client_error(mock_pool_request):
    """Test that the client does NOT retry on 4xx client errors."""
    mock_pool_request.return_value = create_mock_pool_response(404, b"Not Found")

    response = await async_client.request("GET", "https://example.com")

    # 4xx errors are not retried by the default transport
    assert response.status_code == 404
    assert mock_pool_request.call_count == 1


# --- Tests for get_async_http_client context manager ---
# These tests check that the context manager correctly constructs
# and closes a new client, using either the global transport
# or a new proxy-configured transport.


@patch("src.chimera_intel.core.http_client.AsyncClient")
@patch("src.chimera_intel.core.http_client.async_transport")  # Patch the global instance
async def test_get_client_no_proxy(
    mock_global_transport, mock_client_class_call, mock_network_timeout
):
    """Test get_async_http_client without proxies uses the global transport."""

    mock_client_instance = MagicMock(name="ClientInstance")
    mock_client_instance.aclose = AsyncMock()
    mock_client_class_call.return_value = mock_client_instance

    async with get_async_http_client() as client:
        assert client == mock_client_instance

    # Check that the global transport was used
    mock_client_class_call.assert_called_once()
    call_kwargs = mock_client_class_call.call_args[1]

    assert call_kwargs["transport"] == mock_global_transport
    assert isinstance(call_kwargs["timeout"], Timeout)
    # FIX: Access .read (or .connect, .write) instead of .timeout
    assert call_kwargs["timeout"].read == 30.0  # From mock_network_timeout
    assert call_kwargs["headers"] == {"User-Agent": "Chimera-Intel/6.0"}

    mock_client_instance.aclose.assert_called_once()


@patch("src.chimera_intel.core.http_client.AsyncClient")
@patch(
    "src.chimera_intel.core.http_client.httpx.AsyncHTTPTransport"
)  # FIX: Patch the correct path
async def test_get_client_with_proxy(
    mock_transport_class_call, mock_client_class_call, mock_network_timeout
):
    """Test get_async_http_client with proxies creates a new transport."""

    mock_transport_instance = MagicMock(name="ProxyTransportInstance")
    mock_client_instance = MagicMock(name="ProxyClientInstance")
    mock_client_instance.aclose = AsyncMock()

    mock_transport_class_call.return_value = mock_transport_instance
    mock_client_class_call.return_value = mock_client_instance

    proxy_config = {"http": "http://user:pass@10.10.1.10:3128"}

    async with get_async_http_client(proxies=proxy_config) as client:
        assert client == mock_client_instance

    # Check that a *new* transport was created with proxy info
    mock_transport_class_call.assert_called_once_with(
        retries=3, proxy="http://user:pass@10.10.1.10:3128"
    )

    # Check that the client was created with this new transport
    mock_client_class_call.assert_called_once()
    call_kwargs = mock_client_class_call.call_args[1]

    assert call_kwargs["transport"] == mock_transport_instance
    assert isinstance(call_kwargs["timeout"], Timeout)
    # FIX: Access .read (or .connect, .write) instead of .timeout
    assert call_kwargs["timeout"].read == 30.0  # From mock_network_timeout
    assert call_kwargs["headers"] == {"User-Agent": "Chimera-Intel/6.0"}

    mock_client_instance.aclose.assert_called_once()