import pytest
import httpx
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import Timeout

# Import the actual objects from the source file
from src.chimera_intel.core.http_client import async_client, get_async_http_client, NETWORK_TIMEOUT

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
def mock_async_transport():
    """
    Mocks the handle_async_request method of the base AsyncHTTPTransport.
    
    This is the layer that httpx uses to send requests and handle retries.
    By mocking this, we can test the retry behavior configured
    on the global `async_client` instance.
    """
    with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_handle:
        yield mock_handle


# --- Tests for global async_client ---
# These tests check the behavior of the global client, specifically
# its retry logic which is configured via its transport.

async def test_global_client_transport_success(mock_async_transport):
    """Test a successful request via the transport."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "ok"}
    mock_response.is_error = False
    mock_response.is_success = True
    # The transport returns the response
    mock_async_transport.return_value = mock_response

    response = await async_client.request("GET", "https://example.com")

    assert response.status_code == 200
    # Note: .json() is not async on a MagicMock
    assert response.json() == {"status": "ok"}
    assert mock_async_transport.call_count == 1
    
    # Check args of the transport call
    called_request = mock_async_transport.call_args[0][0]
    assert called_request.method == "GET"
    assert str(called_request.url) == "https://example.com/"


@pytest.mark.parametrize("status_code, exception_class", [
    (500, httpx.HTTPStatusError),
    (502, httpx.HTTPStatusError),
    (503, httpx.HTTPStatusError),
    (504, httpx.HTTPStatusError),
])
async def test_global_client_retry_on_server_error(mock_async_transport, status_code, exception_class):
    """Test that the client retries on 5xx server errors."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = status_code
    mock_response.request = MagicMock(url="https://example.com")
    mock_response.is_error = True
    mock_response.is_success = False
    mock_response.raise_for_status.side_effect = exception_class(
        f"{status_code} Server Error", request=mock_response.request, response=mock_response
    )
    
    mock_async_transport.return_value = mock_response

    # The global transport is configured with retries=3.
    # This means 1 initial call + 3 retries = 4 attempts.
    
    with pytest.raises(httpx.HTTPStatusError):
        await async_client.request("GET", "https://example.com")

    # The transport's handle_async_request should be called 4 times
    assert mock_async_transport.call_count == 4


async def test_global_client_retry_on_timeout(mock_async_transport):
    """Test that the client retries on httpx.TimeoutException."""
    # The transport itself will raise TimeoutException
    mock_async_transport.side_effect = httpx.TimeoutException("Timeout")

    with pytest.raises(httpx.TimeoutException):
        await async_client.request("GET", "https://example.com")

    # Should be called 1 initial + 3 retries = 4 times
    assert mock_async_transport.call_count == 4


async def test_global_client_no_retry_on_client_error(mock_async_transport):
    """Test that the client does NOT retry on 4xx client errors."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 404
    mock_response.request = MagicMock(url="https://example.com")
    mock_response.is_error = True # 4xx is an error
    mock_response.is_success = False
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "404 Not Found", request=mock_response.request, response=mock_response
    )
    
    mock_async_transport.return_value = mock_response

    with pytest.raises(httpx.HTTPStatusError):
        await async_client.request("GET", "https://example.com")

    # 4xx errors are not retried by the default transport
    assert mock_async_transport.call_count == 1


# --- Tests for get_async_http_client context manager ---
# These tests check that the context manager correctly constructs
# and closes a new client, using either the global transport
# or a new proxy-configured transport.

@patch("src.chimera_intel.core.http_client.AsyncClient")
@patch("src.chimera_intel.core.http_client.async_transport") # Patch the global instance
async def test_get_client_no_proxy(mock_global_transport, mock_client_class_call, mock_network_timeout):
    """Test get_async_http_client without proxies uses the global transport."""
    
    mock_client_instance = MagicMock(name="ClientInstance")
    mock_client_instance.aclose = AsyncMock()
    mock_client_class_call.return_value = mock_client_instance

    async with get_async_http_client() as client:
        assert client == mock_client_instance

    # Check that the global transport was used
    mock_client_class_call.assert_called_once()
    call_kwargs = mock_client_class_call.call_args[1]
    
    assert call_kwargs['transport'] == mock_global_transport
    assert isinstance(call_kwargs['timeout'], Timeout)
    assert call_kwargs['timeout'].timeout == 30.0 # From mock_network_timeout
    assert call_kwargs['headers'] == {"User-Agent": "Chimera-Intel/6.0"}
    
    mock_client_instance.aclose.assert_called_once()


@patch("src.chimera_intel.core.http_client.AsyncClient")
@patch("src.chimera_intel.core.http_client.AsyncHTTPTransport") # Patch the class
async def test_get_client_with_proxy(mock_transport_class_call, mock_client_class_call, mock_network_timeout):
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
        retries=3,
        proxy="http://user:pass@10.10.1.10:3128"
    )
    
    # Check that the client was created with this new transport
    mock_client_class_call.assert_called_once()
    call_kwargs = mock_client_class_call.call_args[1]
    
    assert call_kwargs['transport'] == mock_transport_instance
    assert isinstance(call_kwargs['timeout'], Timeout)
    assert call_kwargs['timeout'].timeout == 30.0 # From mock_network_timeout
    assert call_kwargs['headers'] == {"User-Agent": "Chimera-Intel/6.0"}
    
    mock_client_instance.aclose.assert_called_once()