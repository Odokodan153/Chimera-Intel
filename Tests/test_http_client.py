import pytest
import httpx
from unittest.mock import patch, MagicMock
from src.chimera_intel.core.http_client import EnhancedAsyncClient

# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio


@pytest.fixture
def mock_httpx_async_client():
    """Mocks the underlying httpx.AsyncClient."""
    with patch("httpx.AsyncClient") as mock_client:
        mock_instance = MagicMock()
        mock_instance.request = MagicMock()
        mock_client.return_value = mock_instance
        yield mock_instance


async def test_enhanced_client_request_success(mock_httpx_async_client):
    """Test a successful request."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "ok"}
    mock_httpx_async_client.request.return_value = mock_response

    client = EnhancedAsyncClient()
    response = await client.request("GET", "https://example.com")

    assert response.status_code == 200
    assert await response.json() == {"status": "ok"}
    mock_httpx_async_client.request.assert_called_once_with(
        "GET", "https://example.com", timeout=30, follow_redirects=True
    )


@pytest.mark.parametrize("status_code, exception_class", [
    (500, httpx.HTTPStatusError),
    (502, httpx.HTTPStatusError),
    (503, httpx.HTTPStatusError),
    (504, httpx.HTTPStatusError),
])
async def test_enhanced_client_retry_on_server_error(mock_httpx_async_client, status_code, exception_class):
    """Test that the client retries on 5xx server errors and then fails."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = status_code
    mock_response.request = MagicMock()
    # Simulate the response raising a status error
    mock_response.raise_for_status.side_effect = exception_class(
        f"{status_code} Server Error", request=mock_response.request, response=mock_response
    )
    
    mock_httpx_async_client.request.return_value = mock_response

    client = EnhancedAsyncClient(retries=3)
    
    with pytest.raises(httpx.HTTPStatusError):
        await client.request("GET", "https://example.com")

    # Should be called 1 initial + 3 retries = 4 times
    assert mock_httpx_async_client.request.call_count == 4


async def test_enhanced_client_retry_on_timeout(mock_httpx_async_client):
    """Test that the client retries on httpx.TimeoutException."""
    mock_httpx_async_client.request.side_effect = httpx.TimeoutException("Timeout")

    client = EnhancedAsyncClient(retries=3)
    
    with pytest.raises(httpx.TimeoutException):
        await client.request("GET", "https://example.com")

    # Should be called 1 initial + 3 retries = 4 times
    assert mock_httpx_async_client.request.call_count == 4


async def test_enhanced_client_no_retry_on_client_error(mock_httpx_async_client):
    """Test that the client does NOT retry on 4xx client errors."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 404
    mock_response.request = MagicMock()
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "404 Not Found", request=mock_response.request, response=mock_response
    )
    
    mock_httpx_async_client.request.return_value = mock_response

    client = EnhancedAsyncClient(retries=3)
    
    with pytest.raises(httpx.HTTPStatusError):
        await client.request("GET", "https://example.com")

    # Should be called only once
    assert mock_httpx_async_client.request.call_count == 1