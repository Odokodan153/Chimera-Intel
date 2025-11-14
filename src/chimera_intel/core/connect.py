"""
Connect Module for Chimera Intel.

Dedicated integrations with public APIs and tools for 
encrypted/private messaging platforms (e.g., Telegram channels, 
Discord servers, Signal open groups) to passively monitor 
public group chatter for target mentions or illicit activity.

NOTE:
- Telegram will require interactive login (phone, code, 2FA) on first run 
  to create a 'chimera_intel.session' file.
- Discord requires a Bot Token and the bot MUST be invited to any
  target servers before running this tool.
"""

import typer
import asyncio
import logging
from typing import List, Dict, Any, Optional
import discord
from telethon import TelegramClient
from telethon.errors import ChannelInvalidError, ChannelPrivateError
from .utils import console, save_or_print_results
from .database import save_scan_to_db
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)

connect_app = typer.Typer(
    name="connect",
    help="Monitors public chatter on messaging platforms.",
)

# --- Real Telegram Scraper ---
async def _scrape_telegram(target: str, channels: List[str]) -> List[Dict[str, Any]]:
    """(Real) Scrapes public Telegram channels for a target keyword."""
    if not API_KEYS.telegram_api_id or not API_KEYS.telegram_api_hash:
        console.print("  - [yellow]Telegram:[/yellow] SKIPPED (TELEGRAM_API_ID or TELEGRAM_API_HASH not set).")
        return []
        
    if not channels:
        return []

    console.print(f"  - [cyan]Telegram:[/cyan] Initializing client... (may require login)")
    
    # Telethon creates a session file to store login details.
    session_file = "chimera_intel.session"
    results: List[Dict[str, Any]] = []

    try:
        async with TelegramClient(session_file, int(API_KEYS.telegram_api_id), API_KEYS.telegram_api_hash) as client:
            console.print("  - [cyan]Telegram:[/cyan] Client started. Searching channels...")
            for channel_username in channels:
                try:
                    entity = await client.get_entity(channel_username)
                    # Search the channel for the target keyword
                    async for message in client.iter_messages(entity, search=target, limit=20):
                        results.append({
                            "platform": "Telegram",
                            "channel": getattr(entity, 'title', channel_username),
                            "author_id": message.sender_id,
                            "message": message.text,
                            "url": f"https://t.me/{channel_username}/{message.id}"
                        })
                except (ChannelInvalidError, ChannelPrivateError):
                    console.print(f"  - [red]Telegram Error:[/red] Cannot access channel '{channel_username}'. Skipping.")
                except ValueError:
                     console.print(f"  - [red]Telegram Error:[/red] Channel '{channel_username}' not found. Skipping.")
                except Exception as e:
                    console.print(f"  - [red]Telegram Error ({channel_username}):[/red] {e}")
    
    except Exception as e:
        console.print(f"[bold red]Telegram connection failed:[/bold red] {e}")
        console.print("  - [yellow]Hint:[/yellow] First-time setup is interactive. Run this command in a non-containerized terminal.")
    
    return results

# --- Real Discord Scraper ---

class SearchBot(discord.Client):
    """A custom discord.py Client to perform a one-off search and exit."""
    def __init__(self, target: str, channel_ids: List[str], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target = target.lower()
        self.channel_ids = channel_ids
        self.results: List[Dict[str, Any]] = []

    async def on_ready(self):
        console.print(f"  - [cyan]Discord:[/cyan] Logged in as {self.user}. Searching...")
        for channel_id_str in self.channel_ids:
            try:
                channel_id = int(channel_id_str)
                channel = await self.fetch_channel(channel_id)
                
                if isinstance(channel, discord.TextChannel):
                    console.print(f"  - [cyan]Discord:[/cyan] Searching #{channel.name} in {channel.guild.name}...")
                    # Iterate message history to find the target
                    async for message in channel.history(limit=500): # Check last 500 messages
                        if self.target in message.content.lower():
                            self.results.append({
                                "platform": "Discord",
                                "server": channel.guild.name,
                                "channel": channel.name,
                                "author": str(message.author),
                                "message": message.content,
                                "url": message.jump_url
                            })
                else:
                    console.print(f"  - [yellow]Discord Warning:[/yellow] Channel ID {channel_id} is not a Text Channel.")

            except discord.NotFound:
                console.print(f"  - [red]Discord Error:[/red] Channel ID {channel_id_str} not found.")
            except discord.Forbidden:
                console.print(f"  - [red]Discord Error:[/red] Bot lacks permissions for channel {channel_id_str}.")
            except ValueError:
                 console.print(f"  - [red]Discord Error:[/red] '{channel_id_str}' is not a valid channel ID.")
            except Exception as e:
                console.print(f"  - [red]Discord Error (Channel {channel_id_str}):[/red] {e}")
        
        # Once all searches are done, close the client
        await self.close()

async def _scrape_discord(target: str, channel_ids: List[str]) -> List[Dict[str, Any]]:
    """(Real) Scrapes public Discord servers for a target keyword."""
    if not API_KEYS.discord_bot_token:
        console.print("  - [yellow]Discord:[/yellow] SKIPPED (DISCORD_BOT_TOKEN not set).")
        return []
        
    if not channel_ids:
        return []

    # Discord bots need 'message_content' intent to read messages
    intents = discord.Intents.default()
    intents.message_content = True
    
    bot = SearchBot(target=target, channel_ids=channel_ids, intents=intents)

    try:
        await bot.start(API_KEYS.discord_bot_token)
        # The bot will run until it calls `await self.close()` in on_ready
        return bot.results
    except discord.LoginFailure:
        console.print("[bold red]Discord login failed:[/bold red] Invalid DISCORD_BOT_TOKEN.")
        return []
    except Exception as e:
        console.print(f"[bold red]Discord client error:[/bold red] {e}")
        return []

async def scrape_messaging_platforms(
    target: str, 
    telegram_channels: List[str], 
    discord_channels: List[str]
) -> Dict[str, Any]:
    """
    Passively monitors public messaging platforms for target mentions.
    """
    console.print(f"[bold cyan]Starting messaging scrape for target: {target}[/bold cyan]")
    
    tasks = [
        _scrape_telegram(target, telegram_channels),
        _scrape_discord(target, discord_channels)
    ]
    
    results = await asyncio.gather(*tasks)
    
    # Flatten the list of lists
    all_mentions = [mention for platform_results in results for mention in platform_results]
    
    return {
        "target": target,
        "mentions_found": all_mentions,
        "total_mentions": len(all_mentions)
    }

@connect_app.command("messaging-scrapper")
def run_messaging_scrapper(
    target: str = typer.Argument(..., help="The target keyword to search for (e.g., company name, domain, CVE)."),
    telegram_channels: List[str] = typer.Option(
        None, 
        "--telegram-channel", "-tc", 
        help="Public Telegram channel/group username (e.g., 'durov') to search. Can be used multiple times."
    ),
    discord_channels: List[str] = typer.Option(
        None, 
        "--discord-channel", "-dc", 
        help="Discord Channel ID to search. Bot must have read access. Can be used multiple times."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Scrapes public Telegram & Discord for mentions of a target.
    """
    # Ensure lists are not None
    if not telegram_channels: telegram_channels = []
    if not discord_channels: discord_channels = []

    if not telegram_channels and not discord_channels:
        console.print("[bold red]Error:[/bold red] You must provide at least one --telegram-channel or --discord-channel to search.")
        raise typer.Exit(code=1)

    try:
        results = asyncio.run(scrape_messaging_platforms(target, telegram_channels, discord_channels))
        
        if results["total_mentions"] > 0:
            console.print(f"\n[bold green]Success:[/bold green] Found {results['total_mentions']} total mentions.")
        else:
            console.print("\n[bold]No mentions found for this target.[/bold]")

        save_or_print_results(results, output_file)
        save_scan_to_db(target=target, module="connect_messaging_scrapper", data=results)
        
    except Exception as e:
        console.print(f"[bold red]Error during scrape:[/bold red] {e}")
        raise typer.Exit(code=1)

@connect_app.callback()
def callback():
    """
    Passively monitor public group chatter for target mentions or illicit activity.
    """
    pass