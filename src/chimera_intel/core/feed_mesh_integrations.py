"""
Chimera-Intel Real-Time Feed Mesh Integrations

This module provides handlers for integrating external real-time threat feeds
into the core EventMesh, and defines CLI commands to start the feeds.
"""

import asyncio
import websockets
import json
import httpx
import typer
from typing import Callable, Coroutine, Any, Dict
from urllib.parse import urlparse

# --- Assumed Core Component Instances ---
from .event_mesh import event_mesh, EventMesh  # <<< FIX: Added EventMesh type import
from .config_loader import ConfigLoader
from .logger_config import setup_logging
from .utils import console

logger = setup_logging()

# Define the Typer app for this module
feed_mesh_app = typer.Typer()


class FeedIntegrator:
    """
    Manages the connection and data ingestion for real-time threat feeds.
    """

    def __init__(self, event_mesh_instance: EventMesh, config: ConfigLoader):
        self.event_mesh = event_mesh_instance
        self.config = config
        self.http_client = httpx.AsyncClient()
        self._tasks = []
        logger.info("FeedIntegrator initialized.")

    async def _start_greynoise_stream(self):
        """
        Connects to the GreyNoise stream.
        This example polls the Community API. A real enterprise implementation
        would use the WebSocket "GNQL" stream.
        """
        api_key = self.config.get_api_key("greynoise")
        if not api_key:
            logger.warning("No GreyNoise API key found. Skipping GreyNoise feed.")
            return

        url = "https://api.greynoise.io/v2/interesting"
        headers = {"key": api_key, "Accept": "application/json"}
        
        while True:
            try:
                logger.info("Polling GreyNoise for 'interesting' IPs...")
                response = await self.http_client.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    for ip_data in data.get("ip_events", []):
                        await self.event_mesh.publish("greynoise_feed", ip_data)
                        logger.debug(f"Published GreyNoise data for {ip_data.get('ip')}")
                else:
                    logger.error(f"GreyNoise API error: {response.status_code} {response.text}")
                
                await asyncio.sleep(300) # Poll every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in GreyNoise feed loop: {e}")
                await asyncio.sleep(600) # Back off on error

    async def _start_certstream_stream(self):
        """
        Connects to the Certstream WebSocket feed for new SSL certificates.
        """
        uri = "wss://certstream.calidog.io/"
        while True:
            try:
                logger.info("Connecting to Certstream WebSocket...")
                async with websockets.connect(uri) as websocket:
                    logger.info("Successfully connected to Certstream.")
                    console.print("[feed-mesh] [bold green]Certstream[/bold green] feed connected.", style="dim")
                    async for message in websocket:
                        data = json.loads(message)
                        if data.get("message_type") == "certificate_update":
                            await self.event_mesh.publish("certstream_feed", data)
                            logger.debug("Published Certstream update.")
                            
            except Exception as e:
                logger.error(f"Certstream WebSocket disconnected: {e}. Reconnecting in 60s.")
                console.print(f"[feed-mesh] [bold red]Certstream[/bold red] disconnected. Reconnecting...", style="dim")
                await asyncio.sleep(60)

    async def _start_malware_feed(self):
        """
        Connects to a live malware feed (e.g., URLhaus).
        """
        url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
        logger.info("Starting Malware Feed (URLhaus) poller...")
        
        while True:
            try:
                logger.info("Polling URLhaus for recent malware URLs...")
                response = await self.http_client.get(url, timeout=30.0)
                response.raise_for_status()
                
                csv_data = response.text.splitlines()
                if not csv_data:
                    await asyncio.sleep(300)
                    continue

                console.print(f"[feed-mesh] [bold green]URLhaus[/bold green] feed polled, {len(csv_data)} lines.", style="dim")
                for line in csv_data:
                    if line.startswith("#"):
                        continue
                    try:
                        parts = [p.strip('"') for p in line.split('","')]
                        if len(parts) >= 9:
                            malware_info = {
                                "source": "urlhaus", "timestamp": parts[1], "url": parts[2],
                                "status": parts[3], "threat": parts[5], "tags": parts[6].split(','),
                                "reporter": parts[8],
                            }
                            await self.event_mesh.publish("malware_feed", malware_info)
                    except Exception as e:
                        logger.warning(f"Failed to parse URLhaus line: {e}")

                await asyncio.sleep(300) # Poll every 5 minutes

            except Exception as e:
                logger.error(f"Error in Malware Feed (URLhaus) loop: {e}")
                console.print(f"[feed-mesh] [bold red]URLhaus[/bold red] feed error. Reconnecting...", style="dim")
                await asyncio.sleep(600) # Back off on error

    async def start_all_feeds(self):
        """Starts all configured feed integrator tasks concurrently."""
        logger.info("Starting all real-time feed integrations...")
        self._tasks = [
            asyncio.create_task(self._start_greynoise_stream()),
            asyncio.create_task(self._start_certstream_stream()),
            asyncio.create_task(self._start_malware_feed()),
        ]
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def stop_all_feeds(self):
        """Stops all running feed tasks."""
        logger.info("Stopping all real-time feed integrations...")
        for task in self._tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("All feed integrations stopped.")


class RealTimeAlerter:
    """
    Subscribes to the event mesh and provides low-latency alerts.
    """
    def __init__(self, event_mesh_instance: EventMesh, config: ConfigLoader):
        self.event_mesh = event_mesh_instance
        self.domains = config.get("feed_mesh.alert_domains", [])
        self.alert_callback: Callable[[str, Dict[str, Any]], Coroutine[Any, Any, None]] = self._default_alert_callback
        logger.info(f"RealTimeAlerter initialized. Monitoring domains: {self.domains}")

    async def _default_alert_callback(self, topic: str, alert_data: Dict[str, Any]):
        """Default alert action: log and publish to a new 'alerts' topic."""
        summary = alert_data.get('summary')
        logger.warning(f"LOW-LATENCY ALERT on topic '{topic}': {summary}")
        console.print(f"\n[bold red]LOW-LATENCY ALERT:[/bold red] {summary}")
        await self.event_mesh.publish("alerts", alert_data)

    def set_alert_callback(self, callback: Callable[[str, Dict[str, Any]], Coroutine[Any, Any, None]]):
        self.alert_callback = callback

    async def _monitor_certstream(self, data: Dict[str, Any]):
        """Callback for the 'certstream_feed' topic."""
        if not self.domains: return
        try:
            domain = data.get("data", {}).get("leaf_cert", {}).get("subject", {}).get("CN")
            if not domain: return

            for monitored_domain in self.domains:
                if domain.endswith(f".{monitored_domain}") or domain == monitored_domain:
                    alert = {
                        "summary": f"New certificate issued for monitored domain: {domain}",
                        "domain": domain, "type": "certstream_alert", "raw_data": data,
                    }
                    await self.alert_callback("certstream_feed", alert)
        except Exception as e:
            logger.error(f"Error processing certstream alert: {e}")
            
    async def _monitor_malware(self, data: Dict[str, Any]):
        """Callback for the 'malware_feed' topic."""
        if not self.domains: return
        try:
            url = data.get("url", "")
            domain = urlparse(url).netloc

            for monitored_domain in self.domains:
                if domain.endswith(f".{monitored_domain}") or domain == monitored_domain:
                    alert = {
                        "summary": f"Monitored domain implicated in malware URL: {url}",
                        "domain": domain, "url": url, "threat": data.get("threat"),
                        "type": "malware_alert", "raw_data": data,
                    }
                    await self.alert_callback("malware_feed", alert)
        except Exception as e:
            logger.error(f"Error processing malware alert: {e}")

    async def start_monitoring(self):
        """Subscribes to all relevant feeds to start monitoring for alerts."""
        logger.info("RealTimeAlerter starting monitoring...")
        await self.event_mesh.subscribe("certstream_feed", self._monitor_certstream)
        await self.event_mesh.subscribe("malware_feed", self._monitor_malware)
        # Add subscribers for GreyNoise, etc., as needed
        logger.info("RealTimeAlerter successfully subscribed to feeds.")
        if self.domains:
            console.print(f"[feed-mesh] [bold yellow]RealTimeAlerter[/bold yellow] is monitoring for domains: {self.domains}", style="dim")
        else:
            console.print(f"[feed-mesh] [yellow]RealTimeAlerter[/yellow] has no domains configured.", style="dim")


# --- CLI Command ---

@feed_mesh_app.command("start")
def start_service_cli():
    """
    Start the real-time Feed Mesh services (GreyNoise, Certstream, Malware).
    This will run indefinitely.
    """
    console.print("[bold]Starting Real-Time Feed Mesh...[/bold]")
    config = ConfigLoader()
    
    # We must use the imported module-level event_mesh instance
    if not event_mesh:
        console.print("[bold red]Error: Core EventMesh is not initialized.[/bold red]")
        raise typer.Exit(code=1)

    integrator = FeedIntegrator(event_mesh, config)
    alerter = RealTimeAlerter(event_mesh, config)

    async def run_services():
        console.print("[cyan]Starting FeedIntegrator and RealTimeAlerter...[/cyan]")
        await asyncio.gather(
            integrator.start_all_feeds(),
            alerter.start_monitoring()
        )

    try:
        asyncio.run(run_services())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Feed Mesh service shutting down...[/bold yellow]")
    except Exception as e:
        logger.error(f"Feed Mesh CLI failed: {e}", exc_info=True)
        console.print(f"\n[bold red]An error occurred: {e}[/bold red]")