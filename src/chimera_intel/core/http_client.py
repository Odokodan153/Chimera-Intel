"""
Centralized HTTP client configuration for the Chimera Intel application.

This module creates and configures synchronous and asynchronous HTTP clients
with robust settings for timeouts and retries. By centralizing the client
instances, the entire application benefits from consistent, reliable, and
maintainable network behavior.
"""

import httpx
from httpx import Timeout, Retry, Client, AsyncClient
from .config_loader import CONFIG

# --- Configuration ---
# Load the global network timeout from the Pydantic config object.
NETWORK_TIMEOUT = CONFIG.network.timeout

# Define a robust retry strategy. This object configures how the client
# should behave when a request fails.
retry_strategy = Retry(
    total=3,  # Try each request up to 3 times.
    status_forcelist=[429, 500, 502, 503, 504],  # Retry on these common server/rate-limit error codes.
    backoff_factor=0.5,  # Wait longer between retries (e.g., 0.5s, 1s, 2s).
    respect_retry_after_header=True  # Obey the 'Retry-After' header sent by APIs.
)

# Create the transport layers. The transport is a low-level component that
# handles the actual sending of requests and incorporates the retry strategy.
transport = httpx.HTTPTransport(retries=retry_strategy)
async_transport = httpx.AsyncHTTPTransport(retries=retry_strategy)


# --- Centralized Client Instances ---
# These pre-configured clients are imported and used by all other modules
# in the application for making HTTP requests.

# Synchronous client for regular (def) functions.
sync_client = Client(
    transport=transport,
    timeout=Timeout(NETWORK_TIMEOUT),
    headers={"User-Agent": "Chimera-Intel/6.0"}
)

# Asynchronous client for high-performance (async def) functions.
async_client = AsyncClient(
    transport=async_transport,
    timeout=Timeout(NETWORK_TIMEOUT),
    headers={"User-Agent": "Chimera-Intel/6.0"}
)