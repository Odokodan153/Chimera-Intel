"""
Centralized HTTP client configuration for the Chimera Intel application.

This module creates and configures synchronous and asynchronous HTTP clients
with robust settings for timeouts and retries. By centralizing the client
instances, the entire application benefits from consistent, reliable, and
maintainable network behavior.
"""

import httpx
from httpx import Timeout, Client, AsyncClient
from .config_loader import CONFIG
from .schemas import AppConfig  # Import AppConfig type to resolve the error
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any, cast  # Import cast for type narrowing

# Explicitly cast CONFIG to its AppConfig type to satisfy mypy's type inference.

CONFIG: AppConfig = cast(AppConfig, CONFIG)

# --- Configuration ---
# Load the global network timeout from the Pydantic config object.


NETWORK_TIMEOUT = CONFIG.network.timeout

# --- CHANGE: Correctly configure retries for the transport ---
# The 'retries' parameter on the transport layer handles the retry logic.


transport = httpx.HTTPTransport(retries=3)
async_transport = httpx.AsyncHTTPTransport(retries=3)


# --- Centralized Client Instances ---
# These pre-configured clients are imported and used by all other modules
# in the application for making HTTP requests.

# Synchronous client for regular (def) functions.


sync_client = Client(
    transport=transport,
    timeout=Timeout(NETWORK_TIMEOUT),
    headers={"User-Agent": "Chimera-Intel/6.0"},
)

# Asynchronous client for high-performance (async def) functions.


async_client = AsyncClient(
    transport=async_transport,
    timeout=Timeout(NETWORK_TIMEOUT),
    headers={"User-Agent": "Chimera-Intel/6.0"},
)


@asynccontextmanager
async def get_async_http_client(proxies: Optional[Dict[str, Any]] = None):
    """
    Provides a new AsyncClient instance, primarily for use with dynamic proxy configurations
    (e.g., Tor proxies for dark web monitoring).
    It closes the client automatically upon exit.
    """
    client = None
    try:
        client = AsyncClient(
            transport=async_transport,
            timeout=Timeout(NETWORK_TIMEOUT),
            headers={"User-Agent": "Chimera-Intel/6.0"},
            proxies=proxies,
        )
        yield client
    finally:
        if client:
            await client.aclose()
