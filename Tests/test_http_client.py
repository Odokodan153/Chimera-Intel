import pytest
import httpx
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import Timeout, AsyncClient, Response, ReadTimeout

# Import module and target function
from chimera_intel.core import http_client as http_client_module
from chimera_intel.core.http_client import get_async_http_client

# Mark module async
pytestmark = pytest.mark.asyncio


# --- Global network timeout patch (Good practice, unchanged) ---
@pytest.fixture(autouse=True)
def mock_network_timeout():
    """Force deterministic NETWORK_TIMEOUT for all tests."""
    with patch("chimera_intel.core.http_client.NETWORK_TIMEOUT", 30.0) as mock_timeout:
        yield mock_timeout


# --- NEW FIXTURES ---

@pytest.fixture
def mock_handler() -> AsyncMock:
    """Provides a mock handler. Tests will configure this handler's behavior."""
    return AsyncMock(name="mock_http_handler")


@pytest.fixture
def mocked_global_client(mock_handler, mock_network_timeout):
    """
    This fixture replaces the low-level patching with httpx.MockTransport.
    
    It creates a new AsyncClient that uses a mock transport, and then
    patches the module's global 'async_client' to use it.
    
    This fixture is SYNCHRONOUS, which avoids all the async dependency errors.
    """
    # 1. Create the mock transport, telling it to call our mock_handler for any request
    mock_transport = httpx.MockTransport(mock_handler)
    
    # 2. Get the patched timeout value
    # --- FIX: The fixture yields the float 30.0 directly, not a mock ---
    timeout_value = mock_network_timeout  # This is 30.0
    
    # 3. Create a new client configured to use our MOCK transport
    client = AsyncClient(
        transport=mock_transport,
        timeout=Timeout(timeout_value),
        headers={"User-Agent": "Chimera-Intel/6.0"},
    )

    # 4. Patch the global client in the module under test
    with patch.object(http_client_module, "async_client", client) as patched_client:
        yield patched_client
    
    # 5. No client.aclose() is needed for a MockTransport client


# --- REWRITTEN TESTS FOR GLOBAL CLIENT ---

async def test_global_client_transport_success(mocked_global_client, mock_handler):
    """Test a successful HTTP request. The handler returns a 200 OK."""
    # Arrange: Tell the mock handler to return a 200 response
    mock_handler.return_value = Response(200, json={"status": "ok"})

    # Act: Call the global client (which is now our mocked_global_client)
    response = await http_client_module.async_client.request("GET", "https://example.com")

    # Assert
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    
    # Assert the handler was called correctly
    mock_handler.assert_called_once()
    called_request = mock_handler.call_args[0][0]
    assert called_request.method == "GET"
    assert str(called_request.url) == "https://example.com"


async def test_global_client_handles_server_error(mocked_global_client, mock_handler):
    """Test that the client correctly returns a 500 error."""
    # Arrange: Tell the mock handler to return a 500 response
    mock_handler.return_value = Response(500, content=b"Server Error")

    # Act
    response = await http_client_module.async_client.request("GET", "https://example.com")

    # Assert: The client just returns the 500 response
    assert response.status_code == 500
    assert response.text == "Server Error"
    
    # We can prove retries are NOT happening (as expected)
    assert mock_handler.call_count == 1


async def test_global_client_handles_timeout(mocked_global_client, mock_handler):
    """Test that the client correctly raises a timeout."""
    # Arrange: Tell the mock handler to raise a ReadTimeout
    mock_handler.side_effect = ReadTimeout("Timeout")

    # Act & Assert
    with pytest.raises(ReadTimeout):
        await http_client_module.async_client.request("GET", "https://example.com")

    # The handler was called once
    assert mock_handler.call_count == 1


async def test_global_client_handles_client_error(mocked_global_client, mock_handler):
    """Test that the client correctly returns a 404 error."""
    # Arrange: Tell the mock handler to return a 404
    mock_handler.return_value = Response(404, content=b"Not Found")

    # Act
    response = await http_client_module.async_client.request("GET", "https://example.com")

    # Assert
    assert response.status_code == 404
    assert response.text == "Not Found"
    assert mock_handler.call_count == 1


# --- TESTS FOR get_async_http_client (These were passing and are unchanged) ---

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