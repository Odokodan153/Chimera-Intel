import httpx
from httpx import Timeout, Retry, Client, AsyncClient
from .config_loader import CONFIG

# --- Configuration ---
# Load the global network timeout from our config file
NETWORK_TIMEOUT = CONFIG.get("network", {}).get("timeout", 20.0)

# Define a robust retry strategy. This object configures how the client
# should behave when a request fails.
retry_strategy = Retry(
    total=3,  # Try each request up to 3 times.
    status_forcelist=[429, 500, 502, 503, 504],  # Retry on these HTTP status codes.
    backoff_factor=0.5,  # Wait longer between retries (0.5s, 1s, 2s).
    respect_retry_after_header=True  # Obey the 'Retry-After' header from the API.
)

# Create the transport layers with our retry strategy. The transport is a
# low-level component that handles the actual sending of requests.
transport = httpx.HTTPTransport(retries=retry_strategy)
async_transport = httpx.AsyncHTTPTransport(retries=retry_strategy)


# --- Centralized Client Instances ---
# By defining these clients here, any module in the project can import and use
# a pre-configured, consistent, and robust client for making HTTP requests.
# This avoids duplicating configuration and ensures all network calls are reliable.

# Synchronous client for regular (def) functions
sync_client = Client(
    transport=transport,
    timeout=Timeout(NETWORK_TIMEOUT),
    headers={"User-Agent": "Chimera-Intel/6.0"}
)

# Asynchronous client for high-performance (async def) functions
async_client = AsyncClient(
    transport=async_transport,
    timeout=Timeout(NETWORK_TIMEOUT),
    headers={"User-Agent": "Chimera-Intel/6.0"}
)