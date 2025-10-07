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

    Args:
        proxies: Optional dict with proxy configuration, e.g.:
                 {"http": "http://user:pass@10.10.1.10:3128"}
    """
    client = None
    try:
# If proxies are provided, create a new client with the specified proxy settings.
        if proxies and "http" in proxies:
            transport = httpx.AsyncHTTPTransport(
                retries=3,
                proxy=proxies["http"]  
            )
        else:
            transport = async_transport # Use the default transport if no proxy is specified.

        client = AsyncClient(
            transport=transport,
            timeout=Timeout(NETWORK_TIMEOUT),
            headers={"User-Agent": "Chimera-Intel/6.0"},
        )
        yield client

    finally:
        if client:
            await client.aclose()