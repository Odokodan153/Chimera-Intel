import httpx
from httpx import Timeout, Retry, Client, AsyncClient
from .config_loader import CONFIG

# --- Configuration ---
# Load the global network timeout from our config file
NETWORK_TIMEOUT = CONFIG.get("network", {}).get("timeout", 20.0)

# Define a robust retry strategy:
# - Try up to 3 times.
# - Respect 'Retry-After' headers from the API.
# - Use a "backoff factor" to wait longer between retries (e.g., 0.5s, 1s, 2s).
# - Retry on 5xx server errors.
retry_strategy = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    backoff_factor=0.5,
    respect_retry_after_header=True
)

# Create the transport layer with our retry strategy
transport = httpx.HTTPTransport(retries=retry_strategy)
async_transport = httpx.AsyncHTTPTransport(retries=retry_strategy)

# --- Centralized Client Instances ---
# Any module in our project can now import these pre-configured clients.

# Synchronous client for regular functions
sync_client = Client(
    transport=transport,
    timeout=Timeout(NETWORK_TIMEOUT),
    headers={"User-Agent": "Chimera-Intel/6.0"}
)

# Asynchronous client for high-performance functions
async_client = AsyncClient(
    transport=async_transport,
    timeout=Timeout(NETWORK_TIMEOUT),
    headers={"User-Agent": "Chimera-Intel/6.0"}
)