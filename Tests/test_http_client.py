import pytest
import httpx
import httpcore
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import Timeout, AsyncClient  # <-- Import AsyncClient

# Import the actual objects from the source file
# --- FIX: Relative import for pytest compatibility ---
# We import the module to patch the global client inside it
from chimera_intel.core import http_client as http_client_module
from chimera_intel.core.http_client import get_async_http_client

# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def mock_network_timeout():
    """
    Mocks the global NETWORK_TIMEOUT constant *where it is used*
    to ensure a predictable value for tests.
    """
    with patch("chimera_intel.core.http_client.NETWORK_TIMEOUT", 30.0) as mock_timeout:
        yield mock_timeout


# --- START: FIX for global client and event loop ---

@pytest.fixture
async def event_loop_client(mock_network_timeout):
    """
    Provides a fresh AsyncClient instance created within the test's
    event loop, preventing "Event loop is closed" errors.
    This client replaces the global 'async_client' for the duration
    of the test.
    """
    # Create a new client and transport *within* the test's event loop
    transport = httpx.AsyncHTTPTransport(retries=3)
    # Get the mocked timeout value (30.0)
    timeout_value = mock_network_timeout.return_value
    client = AsyncClient(
        transport=transport,
        timeout=Timeout(timeout_value),
        headers={"User-Agent": "Chimera-Intel/6.0"},
    )
    
    # Patch the global 'async_client' in the source module
    # This ensures tests calling the global client use this new instance
    with patch.object(http_client_module, "async_client", client):
        yield client
    
    # Ensure the new client is properly closed after the test
    await client.aclose()


@pytest.fixture
def mock_pool_request(event_loop_client): # <-- Depends on the new event_loop_client
    """
    Mocks the underlying pool request method ('request'), which is called
    by the pool's 'handle_async_request'. This allows the
    pool's *own* retry logic to execute.
    
    This now patches the pool of the fresh 'event_loop_client'.
    """
    with patch.object(
        event_loop_client._transport._pool,  # <-- Patch the pool on the new client
        "request",
        new_callable=AsyncMock,
    ) as mock_handle:
        yield mock_handle

# --- END: FIX for global client and event loop ---


# --- Helper to create a mock pool response ---
def create_mock_pool_response(status_code, content):
    """
    Creates a mock (status, headers, stream, extensions) tuple.
    This is the format returned by the pool's 'request' method.
    """
    headers = [(b"content-type", b"application/json")]

    # Create a simple async generator for the content
    async def async_iterator():
        yield content
        
    # Create a mock stream object
    # We can't assign to 'aclose' on a generator.
    # Instead, create a MagicMock and assign the iterator
    # and a new AsyncMock to its attributes.
    stream_mock = MagicMock()
    # __aiter__ is a method that, when called, returns an async iterator
    # Here, we set the *attribute* to the generator function
    # When httpx calls stream_mock.__aiter__(), it will call our function
    # and get the generator (async iterator) back.
    stream_mock.__aiter__ = async_iterator
    stream_mock.aclose = AsyncMock()
    
    # This tuple is the correct return type for the 'request' method
    return (status_code, headers, stream_mock, {})


# --- Tests for global async_client ---
# These tests will now use the patched 'event_loop_client'

async def test_global_client_transport_success(mock_pool_request):
    """Test a successful request via the transport."""
    mock_pool_request.return_value = create_mock_pool_response(
        200, b'{"status": "ok"}'
    )

    # We use the imported module's client, which is patched
    response = await http_client_module.async_client.request("GET", "https://example.com")

    assert response.status_code == 200
    # FIX: We must 'await response.aread()' before calling '.json()'
    # on an async response that wasn't pre-loaded.
    # Alternatively, .json() will fail with JSONDecodeError on an empty
    # string if the read failed silently due to loop issues.
    await response.aread()
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

    response = await http_client_module.async_client.request("GET", "https://example.com")

    # The final response should be the error
    assert response.status_code == status_code
    # The pool's 'request' method should be called 4 times (1 initial + 3 retries)
    assert mock_pool_request.call_count == 4


async def test_global_client_retry_on_timeout(mock_pool_request):
    """Test that the client retries on httpcore.ReadTimeout."""
    mock_pool_request.side_effect = httpcore.ReadTimeout("Timeout")

    with pytest.raises(httpx.TimeoutException):
        await http_client_module.async_client.request("GET", "https://example.com")

    # Should be called 1 initial + 3 retries = 4 times
    assert mock_pool_request.call_count == 4


async def test_global_client_no_retry_on_client_error(mock_pool_request):
    """Test that the client does NOT retry on 4xx client errors."""
    mock_pool_request.return_value = create_mock_pool_response(404, b"Not Found")

    response = await http_client_module.async_client.request("GET", "https://example.com")

    # 4xx errors are not retried
    assert response.status_code == 404
    assert mock_pool_request.call_count == 1


# --- Tests for get_async_http_client context manager ---
# These tests were not failing, so they remain unchanged.

@patch("chimera_intel.core.http_client.AsyncClient")
@patch("chimera_intel.core.http_client.httpx.AsyncHTTPTransport") 
async def test_get_client_no_proxy(
    mock_transport_class_call, mock_client_class_call, mock_network_timeout
):
    """Test get_async_http_client without proxies uses a new transport."""

    mock_transport_instance = MagicMock(name="TransportInstance")
    mock_transport_class_call.return_value = mock_transport_instance

    mock_client_instance = MagicMock(name="ClientInstance")
    mock_client_instance.aclose = AsyncMock()
    mock_client_class_call.return_value = mock_client_instance

    async with get_async_http_client() as client:
        assert client == mock_client_instance

    # Check that a *new* transport was created with default retries
    mock_transport_class_call.assert_called_once_with(retries=3)
    
    # Check that the client was created with this new transport
    mock_client_class_call.assert_called_once()
    call_kwargs = mock_client_class_call.call_args[1]

    assert call_kwargs["transport"] == mock_transport_instance
    assert isinstance(call_kwargs["timeout"], Timeout)
    assert call_kwargs["timeout"].read == 30.0  # From mock_network_timeout
    assert call_kwargs["headers"] == {"User-Agent": "Chimera-Intel/6.0"}

    mock_client_instance.aclose.assert_called_once()


@patch("chimera_intel.core.http_client.AsyncClient")
@patch("chimera_intel.core.http_client.httpx.AsyncHTTPTransport")
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
    assert call_kwargs["timeout"].read == 30.0  # From mock_network_timeout
    assert call_kwargs["headers"] == {"User-Agent": "Chimera-Intel/6.0"}

    mock_client_instance.aclose.assert_called_once()