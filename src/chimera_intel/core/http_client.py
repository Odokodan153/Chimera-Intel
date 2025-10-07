import httpx
from httpx import AsyncClient, Client, Timeout
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any, cast


from .config_loader import CONFIG as RAW_CONFIG
from .schemas import AppConfig

# Cast the raw config to the AppConfig schema for proper type hinting and access.


CONFIG: AppConfig = cast(AppConfig, RAW_CONFIG)

# Define a global network timeout loaded from the application's configuration.


NETWORK_TIMEOUT = CONFIG.network.timeout

# Define reusable HTTP transports with a built-in retry mechanism for resilience.
# This helps handle transient network errors automatically.


transport = httpx.HTTPTransport(retries=3)
async_transport = httpx.AsyncHTTPTransport(retries=3)

# Global synchronous client for parts of the application that don't use async.
# It's configured with the standard transport, timeout, and a custom User-Agent.


sync_client = Client(
    transport=transport,
    timeout=Timeout(NETWORK_TIMEOUT),
    headers={"User-Agent": "Chimera-Intel/6.0"},
)

# Global asynchronous client for general-purpose, non-proxied API calls.
# Reusing this client instance benefits from connection pooling.


async_client = AsyncClient(
    transport=async_transport,
    timeout=Timeout(NETWORK_TIMEOUT),
    headers={"User-Agent": "Chimera-Intel/6.0"},
)


@asynccontextmanager
async def get_async_http_client(proxies: Optional[Dict[str, Any]] = None):
    """
    Provides a new AsyncClient instance, primarily for use cases
    requiring proxy support.

    This is an async context manager, which ensures that the client's
    resources are properly managed and its .aclose() method is called
    automatically upon exiting the 'with' block.

    Args:
        proxies: An optional dictionary to configure proxies (e.g.,
                 {"http://": "http://user:pass@10.10.1.10:3128/"}).
    """
    client = None
    try:
        # Create the client, passing the proxies directly to the constructor.

        client = AsyncClient(
            transport=async_transport,
            timeout=Timeout(NETWORK_TIMEOUT),
            headers={"User-Agent": "Chimera-Intel/6.0"},
            proxies=proxies,
        )
        # Yield the client to the 'with' block for use.

        yield client
    finally:
        # Ensure the client is closed to release connections, even if errors occur.

        if client:
            await client.aclose()
