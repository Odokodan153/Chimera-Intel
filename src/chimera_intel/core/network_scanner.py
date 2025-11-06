import typer
import asyncio
import socket
import logging
import re
from typing import List, Optional, Set, Dict, Any

# --- Optional High-Performance DNS ---
try:
    import aiodns
    AIODNS_AVAILABLE = True
    logging.getLogger("aiodns").setLevel(logging.WARNING) # Silence noisy lib
except ImportError:
    aiodns = None # type: ignore
    AIODNS_AVAILABLE = False
# ---

from .schemas import (
    PortScanResult,
    ServiceBanner,
    NetworkScanReport,
)  # Assumes these are updated in schemas.py
from .utils import console, save_or_print_results, is_valid_domain, is_valid_ip
from .database import save_scan_to_db
from .project_manager import resolve_target

logger = logging.getLogger(__name__)

network_scan_app = typer.Typer()

# Common ports to check if none are specified
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900,
    8000, 8008, 8080, 8443,
]
# Ports where we should send an HTTP probe for a banner
HTTP_PROBE_PORTS = {80, 443, 8000, 8008, 8080, 8443}

# Fallback map for common ports not always in socket.getservbyport
CUSTOM_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    8080: "http-proxy",
    8443: "https-alt",
}

# --- Default Configurable Parameters ---
SCAN_TIMEOUT = 3.0
DEFAULT_BANNER_SIZE = 2048 # Increased default
DEFAULT_CONCURRENCY = 100

# --- Banner Parsing Regex ---
RE_HTTP_SERVER = re.compile(r"Server: ([^\r\n]+)", re.IGNORECASE)
RE_SSH_VERSION = re.compile(r"SSH-2.0-([^\s]+)")
RE_FTP_VERSION = re.compile(r"\(vsFTPd ([\d\.]+)\)")


def _parse_port_string(port_string: str) -> List[int]:
    """
    Parses a complex port string (e.g., "22,80,100-110,8080").
    
    Returns:
        List[int]: A sorted list of unique ports.
    """
    ports: Set[int] = set()
    if not port_string:
        return []

    part_regex = re.compile(r"^\d+(-\d+)?$")
    
    parts = port_string.split(',')
    for part in parts:
        part = part.strip()
        if not part_regex.match(part):
            raise ValueError(f"Invalid port format: '{part}'")
        
        if '-' in part:
            start_str, end_str = part.split('-')
            start = int(start_str)
            end = int(end_str)
            if start > end:
                raise ValueError(f"Invalid port range: {start} > {end}")
            if start < 1 or end > 65535:
                 raise ValueError(f"Port range out of bounds (1-65535): {part}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError(f"Port out of bounds (1-65535): {port}")
            ports.add(port)
            
    return sorted(list(ports))


async def _resolve_target_ip(target_domain: str, ipv6: bool = False) -> Optional[str]:
    """
    Resolves a domain name to an IP address (IPv4 or IPv6).
    Prefers aiodns if available, falls back to standard asyncio.
    """
    logger.debug(f"Resolving {target_domain}...")
    query_type = "AAAA" if ipv6 else "A"
    address_family = socket.AF_INET6 if ipv6 else socket.AF_INET

    if AIODNS_AVAILABLE and aiodns:
        try:
            resolver = aiodns.DNSResolver()
            results = await resolver.query(target_domain, query_type)
            if results:
                logger.debug(f"Resolved {target_domain} to {results[0].host} via aiodns")
                return results[0].host
        except aiodns.error.DNSError as e:
            if e.args[0] != 4: # Ignore "No answer"
                logger.warning(f"aiodns query failed for {target_domain}: {e}. Falling back.")
        except Exception as e:
            logger.warning(f"Unexpected aiodns error: {e}. Falling back.")
            
    # Fallback to standard getaddrinfo
    try:
        loop = asyncio.get_event_loop()
        info = await loop.getaddrinfo(
            target_domain, None, family=address_family
        )
        if info:
            ip = info[0][4][0]
            logger.debug(f"Resolved {target_domain} to {ip} via getaddrinfo")
            return ip
    except socket.gaierror:
        logger.error(f"Could not resolve {query_type} record for '{target_domain}'")
    except Exception as e:
        logger.error(f"Unexpected getaddrinfo error for {target_domain}: {e}")
        
    return None


def _get_service_name(port: int) -> str:
    """Gets the service name from socket or custom map."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return CUSTOM_SERVICE_MAP.get(port, "unknown")


def _parse_banner(banner: str, port: int) -> Dict[str, str]:
    """Intelligently parses a banner based on the port."""
    parsed = {"software": "unknown", "version": "unknown"}
    
    if port in HTTP_PROBE_PORTS:
        match = RE_HTTP_SERVER.search(banner)
        if match:
            server_str = match.group(1)
            parts = server_str.split(" ")[0].split("/")
            if len(parts) > 0:
                parsed["software"] = parts[0]
            if len(parts) > 1:
                parsed["version"] = parts[1]
    elif port == 22: # SSH
        match = RE_SSH_VERSION.search(banner)
        if match:
            parsed["software"] = "OpenSSH" # Common, but could be other
            parsed["version"] = match.group(1)
    elif port == 21: # FTP
        match = RE_FTP_VERSION.search(banner)
        if match:
            parsed["software"] = "vsFTPd"
            parsed["version"] = match.group(1)
            
    return parsed


async def _probe_port(
    target_ip: str, port: int, timeout: float, banner_size: int, semaphore: asyncio.Semaphore
) -> PortScanResult:
    """
    Asynchronously probes a single port, controlled by a semaphore.
    """
    result = PortScanResult(port=port, is_open=False)
    
    async with semaphore:
        try:
            family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port, family=family), timeout=timeout
            )
            result.is_open = True

            try:
                banner_data = b""
                if port in HTTP_PROBE_PORTS:
                    probe = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Chimera-Intel-Scanner\r\nConnection: close\r\n\r\n".encode()
                    writer.write(probe)
                    await writer.drain()
                    banner_data = await asyncio.wait_for(reader.read(banner_size), timeout=timeout)
                else:
                    banner_data = await asyncio.wait_for(reader.read(banner_size), timeout=timeout)

                banner_raw = banner_data.decode("utf-8", errors="ignore").strip()

                if banner_raw:
                    service_name = _get_service_name(port)
                    first_line = banner_raw.split("\n")[0].strip("\r")
                    parsed_info = _parse_banner(banner_raw, port)
                    
                    result.service = ServiceBanner(
                        name=service_name,
                        banner=first_line,
                        software=parsed_info["software"],
                        version=parsed_info["version"]
                    )
            except Exception as e:
                logger.debug(f"Could not get banner from {target_ip}:{port}: {e}")
            finally:
                writer.close()
                await writer.wait_closed()

        except asyncio.CancelledError:
            logger.info("Scan cancelled.")
            raise
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            result.is_open = False
        except Exception as e:
            logger.warning(f"Error probing port {target_ip}:{port}: {e}", exc_info=False)
            
    return result


async def run_port_scan(
    target_ip: str, 
    ports: List[int], 
    timeout: float, 
    banner_size: int, 
    concurrency: int
) -> NetworkScanReport:
    """
    Runs an asynchronous port scan, limited by a semaphore.
    """
    logger.info(f"Starting port scan on {target_ip} for {len(ports)} ports (concurrency={concurrency}).")
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [
        asyncio.create_task(_probe_port(target_ip, port, timeout, banner_size, semaphore)) 
        for port in ports
    ]
    
    # Process results as they complete (optional, but good for large scans)
    open_ports: List[PortScanResult] = []
    for f in asyncio.as_completed(tasks):
        try:
            res = await f
            if res.is_open:
                open_ports.append(res)
        except asyncio.CancelledError:
            break # Stop processing if scan is cancelled
        except Exception as e:
            logger.error(f"A scan task failed unexpectedly: {e}")

    logger.info(
        f"Scan complete for {target_ip}. Found {len(open_ports)} open ports."
    )

    return NetworkScanReport(
        target_ip=target_ip,
        ports_scanned=ports,
        open_ports=sorted(open_ports, key=lambda p: p.port), # Sort by port
    )


@network_scan_app.command("run")
def run_cli(
    target: Optional[str] = typer.Argument(
        None, help="The target domain or IP. Uses active project if not provided."
    ),
    ports: Optional[str] = typer.Option(
        None,
        "--ports",
        "-p",
        help=f"Ports to scan (e.g., '22,80', '80-100'). Default: {len(COMMON_PORTS)} common ports.",
    ),
    all_ports: bool = typer.Option(
        False,
        "--all-ports",
        help="Scan all ports (1-65535). Overrides --ports.",
    ),
    concurrency: int = typer.Option(
        DEFAULT_CONCURRENCY,
        "--concurrency",
        "-c",
        help="Number of concurrent scan tasks."
    ),
    timeout: float = typer.Option(
        SCAN_TIMEOUT, 
        "--timeout", 
        "-t", 
        help="Connection timeout per port in seconds."
    ),
    banner_size: int = typer.Option(
        DEFAULT_BANNER_SIZE,
        "--banner-size",
        "-b",
        help="Max bytes to read for service banner."
    ),
    ipv6: bool = typer.Option(
        False,
        "--ipv6",
        help="Scan the target's IPv6 address (AAAA record)."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """
    Performs a non-intrusive network scan for open ports and service banners.
    Supports IPv4/IPv6, concurrency limits, and advanced port selection.
    """
    target_name = resolve_target(target, required_assets=["domain", "ip"])
    if not target_name:
        console.print("[bold red]Error: No target specified and no active project found.[/bold red]")
        raise typer.Exit(code=1)

    if not is_valid_domain(target_name, allow_ip=True) and not is_valid_ip(target_name, allow_ipv6=True):
         console.print(f"[bold red]Invalid target format:[/bold red] {target_name}")
         raise typer.Exit(code=1)

    try:
        if all_ports:
            ports_to_scan = list(range(1, 65536))
        elif ports:
            ports_to_scan = _parse_port_string(ports)
        else:
            ports_to_scan = COMMON_PORTS
    except ValueError as e:
        console.print(f"[bold red]Error parsing ports: {e}[/bold red]")
        raise typer.Exit(code=1)

    if not ports_to_scan:
        console.print("[bold yellow]Warning: No ports specified to scan.[/bold yellow]")
        raise typer.Exit()

    # --- Async Wrapper Function ---
    async def main_async(target_name: str, ports: List[int], config: Dict[str, Any]):
        """Wraps async logic to be called once by asyncio.run()"""
        target_ip = target_name
        use_ipv6 = config['ipv6']
        
        # Resolve target if it's a domain, not an IP
        if not is_valid_ip(target_name, allow_ipv6=True):
            console.print(f"Resolving [cyan]{target_name}[/cyan] (IPv{'6' if use_ipv6 else '4'})...")
            ip = await _resolve_target_ip(target_name, ipv6=use_ipv6)
            if not ip:
                console.print(f"[bold red]Error: Could not resolve target IP for[/bold red] {target_name}")
                return None
            target_ip = ip
            console.print(f"Resolved [cyan]{target_name}[/cyan] to [yellow]{target_ip}[/yellow]")
        else:
            # Check for IP version mismatch
            if use_ipv6 and ":" not in target_ip:
                console.print(f"[bold red]Error: --ipv6 flag used but target is an IPv4 address.[/bold red]")
                return None
            if not use_ipv6 and ":" in target_ip:
                 console.print(f"[bold red]Error: Target is an IPv6 address. Use --ipv6 flag to scan.[/bold red]")
                 return None
            console.print(f"Target is IP [yellow]{target_ip}[/yellow], skipping DNS resolution.")

        console.print(
            f"Starting network scan for [cyan]{target_ip}[/cyan] on {len(ports_to_scan)} ports "
            f"(concurrency={config['concurrency']}, timeout={config['timeout']}s)..."
        )
        return await run_port_scan(
            target_ip, 
            ports_to_scan, 
            timeout=config['timeout'], 
            banner_size=config['banner_size'],
            concurrency=config['concurrency']
        )
    
    # --- Run Async Main Function ONCE ---
    scan_config = {
        "ipv6": ipv6,
        "timeout": timeout,
        "banner_size": banner_size,
        "concurrency": concurrency
    }
    
    try:
        report = asyncio.run(main_async(target_name, ports_to_scan, scan_config))
        if report is None:
            raise typer.Exit(code=1)
            
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan cancelled by user.[/bold red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred during the scan: {e}[/bold red]")
        logger.error(f"Network scan CLI failed: {e}", exc_info=True)
        raise typer.Exit(code=1)

    # --- Process Results ---
    report_dict = report.model_dump()
    save_or_print_results(report_dict, output_file)
    save_scan_to_db(target=target_name, module="network_scanner", data=report_dict)
    console.print(f"Network scan complete for {target_name}.")