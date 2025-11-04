"""
Module for the Real-Time Signals & Global Event Mesh.

This module provides the ingestion and deduplication fabric for real-time
data feeds (e.g., RSS, social media, CERT alerts). It forwards
unique, standardized events to the CorrelationEngine for prioritization
and automated response.
"""

import logging
import asyncio
import feedparser
import hashlib
import typer
from typing import List, Set, Dict, Any, Optional
from datetime import datetime, timezone
from .schemas import Event
from .correlation_engine import CorrelationEngine
from .http_client import async_client
from .utils import console, save_or_print_results
from .config_loader import load_config
from .plugin_manager import PluginManager

logger = logging.getLogger(__name__)

# --- Feed Handlers ---
class RSSFeedHandler:
    """Handles fetching and parsing of RSS feeds."""

    async def fetch(self, config: FeedConfig) -> List[Event]:
        """Fetches an RSS feed and converts entries to standard Events."""
        logger.info(f"Fetching RSS feed: {config.name} from {config.url}")
        events = []
        try:
            response = await async_client.get(config.url, timeout=10.0)
            response.raise_for_status()
            feed = feedparser.parse(response.text)

            for entry in feed.entries:
                # Create a stable unique ID for deduplication
                unique_content = f"{entry.get('id', entry.get('link'))}{entry.get('title')}"
                event_hash = hashlib.sha256(unique_content.encode()).hexdigest()
                
                # Parse timestamp
                timestamp_str = entry.get("published", entry.get("updated", datetime.now(timezone.utc).isoformat()))
                try:
                    # Handle various RSS timestamp formats
                    timestamp = feedparser._parse_date(timestamp_str)
                    timestamp = datetime.fromtimestamp(
                        datetime.timestamp(timestamp), timezone.utc
                    )
                except Exception:
                    timestamp = datetime.now(timezone.utc)

                details = {
                    "title": entry.get("title", "No Title"),
                    "link": entry.get("link", ""),
                    "summary": entry.get("summary", ""),
                    "feed_name": config.name,
                }

                events.append(
                    Event(
                        id=event_hash,
                        timestamp=timestamp.isoformat(),
                        event_type=config.event_type,
                        source=config.name,
                        details=details,
                    )
                )
            logger.debug(f"Fetched {len(events)} items from {config.name}")
            return events
        except Exception as e:
            logger.error(f"Failed to fetch or parse RSS feed {config.name}: {e}")
            return []

# --- Core Event Mesh Class ---

class EventMesh:
    """
    Ingestion and correlation fabric for real-time feeds.

    This class manages multiple feed handlers, polls them at specified
    intervals, deduplicates events, and passes new signals to the
    CorrelationEngine.
    """

    def __init__(
        self,
        correlation_engine: CorrelationEngine,
        feed_configs: List[Dict[str, Any]],
        dedupe_cache_size: int = 10000,
    ):
        self.correlation_engine = correlation_engine
        self.feed_configs = [FeedConfig.model_validate(fc) for fc in feed_configs]
        self.handlers = {
            "rss": RSSFeedHandler(),
            # "twitter": TwitterFeedHandler(), # Example for future expansion
        }
        
        # Deduplication cache (stores event 'id' hashes)
        self.seen_event_ids: Set[str] = set()
        self.dedupe_cache_size = dedupe_cache_size
        
        self.running = False
        logger.info(f"EventMesh initialized with {len(self.feed_configs)} feeds.")
        logger.info(f"Reusing existing CorrelationEngine and AlertPrioritizationEngine.")

    async def _process_feed(self, config: FeedConfig):
        """Internal task to poll a single feed."""
        handler = self.handlers.get(config.type)
        if not handler:
            logger.warning(f"No handler found for feed type '{config.type}' (Feed: {config.name})")
            return

        while self.running:
            try:
                new_events = await handler.fetch(config)
                processed_count = 0

                for event in new_events:
                    if event.id not in self.seen_event_ids:
                        # --- 1. Add to Dedupe Cache ---
                        self.seen_event_ids.add(event.id)
                        
                        # --- 2. Forward to Correlation Engine ---
                        # The Correlation Engine will handle prioritization,
                        # automation, and cross-signal correlation.
                        self.correlation_engine.process_event(event)
                        processed_count += 1
                
                if processed_count > 0:
                    logger.info(f"Processed {processed_count} new events from {config.name}")

                # Prune cache if it gets too large
                if len(self.seen_event_ids) > self.dedupe_cache_size:
                    self.seen_event_ids.clear() # Simple clear, could be more complex (e.g., LRU)
                    logger.info("Deduplication cache reset.")
                    
            except Exception as e:
                logger.error(f"Error in processing loop for feed {config.name}: {e}")
            
            await asyncio.sleep(config.interval_seconds)

    async def start(self):
        """Starts the EventMesh polling tasks."""
        if not self.feed_configs:
            logger.warning("EventMesh starting, but no feeds are configured.")
            return
            
        self.running = True
        console.print(f"[bold green]EventMesh started. Monitoring {len(self.feed_configs)} real-time feeds...[/bold green]")
        
        tasks = [
            asyncio.create_task(self._process_feed(config))
            for config in self.feed_configs
        ]
        
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("EventMesh stopping...")
        finally:
            self.running = False

    def stop(self):
        """Stops the EventMesh."""
        self.running = False
        console.print("[bold yellow]EventMesh shutting down...[/bold yellow]")

# --- Typer CLI Application ---

event_mesh_app = typer.Typer()

@event_mesh_app.command("start")
def start_mesh():
    """
    Starts the Real-Time Event Mesh service.

    This service will continuously monitor all feeds defined in the
    'event_mesh' section of your config.yaml.
    
    New signals will be automatically processed by the
    CorrelationEngine for prioritization and automation.
    """
    console.print("[bold cyan]Initializing Real-Time Event Mesh...[/bold cyan]")
    
    try:
        config = load_config()
        mesh_config = config.get("event_mesh", {})
        feed_configs = mesh_config.get("feeds", [])

        if not feed_configs:
            console.print("[bold yellow]Warning:[/bold yellow] No 'event_mesh.feeds' configured in config.yaml. Exiting.")
            return

        # 1. Initialize the PluginManager (needed by CorrelationEngine)
        plugin_manager = PluginManager()
        plugin_manager.load_plugins()

        # 2. Initialize the CorrelationEngine (which contains the PrioritizationEngine)
        # This reuses the *exact same* engine that the rest of the
        # platform uses, enabling cross-signal correlation.
        correlation_engine = CorrelationEngine(
            plugin_manager=plugin_manager,
            config=config
        )

        # 3. Initialize the EventMesh, passing it the CorrelationEngine
        mesh = EventMesh(
            correlation_engine=correlation_engine,
            feed_configs=feed_configs,
        )

        # 4. Start the asynchronous processing loop
        asyncio.run(mesh.start())

    except FileNotFoundError:
        console.print("[bold red]Error:[/bold red] config.yaml not found. Cannot start Event Mesh.")
    except Exception as e:
        console.print(f"[bold red]Event Mesh failed to start:[/bold red] {e}")
        logger.error(f"Event Mesh crashed: {e}", exc_info=True)


@event_mesh_app.command("feeds")
def list_feeds(
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save feed configuration to a JSON file."
    ),
):
    """
    Lists all configured real-time feeds from config.yaml.
    """
    try:
        config = load_config()
        mesh_config = config.get("event_mesh", {})
        feed_configs = mesh_config.get("feeds", [])
        
        if not feed_configs:
            console.print("[yellow]No Event Mesh feeds configured.[/yellow]")
            return

        console.print(f"Found [bold]{len(feed_configs)}[/bold] configured feeds:")
        save_or_print_results(feed_configs, output_file)

    except FileNotFoundError:
        console.print("[bold red]Error:[/bold red] config.yaml not found.")
    except Exception as e:
        console.print(f"[bold red]Error loading feed config:[/bold red] {e}")