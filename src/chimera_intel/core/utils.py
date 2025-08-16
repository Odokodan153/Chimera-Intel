import json
import re
from rich.console import Console
from rich.json import JSON
from typing import Dict, Any
import logging

from .http_client import sync_client

# Get a logger instance for this specific file


logger = logging.getLogger(__name__)

# Initialize a single console instance, primarily for beautiful user-facing output.


console = Console()


def save_or_print_results(data: Dict[str, Any], output_file: str | None) -> None:
    """
    Handles the output of scan results.

    This function saves the provided data to a JSON file if an output path is given.
    Otherwise, it prints the data to the console in a beautifully formatted and
    syntax-highlighted way using the rich library.

    Args:
        data (Dict[str, Any]): The dictionary containing the scan results.
        output_file (str | None): The file path to save the JSON output.
                                  If None, prints to the console.
    """
    try:
        # The default=str is a safeguard for non-serializable types like datetime.

        json_str = json.dumps(data, indent=4, ensure_ascii=False, default=str)

        if output_file:
            logger.info("Saving results to %s", output_file)
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(json_str)
                # Use console.print for successful, user-facing messages

                console.print(
                    f"[bold green]Successfully saved to {output_file}[/bold green]"
                )
            except Exception as e:
                # Use the logger for error messages

                logger.error("Error saving file to %s: %s", output_file, e)
        else:
            # Use console.print for the primary, formatted output of the tool

            console.print(JSON(json_str))
    except Exception as e:
        logger.error(
            "An unexpected error occurred while preparing results for output: %s", e
        )


def is_valid_domain(domain: str) -> bool:
    """
    Validates if the given string is a plausible domain name using a regular expression.

    Args:
        domain (str): The string to validate as a domain.

    Returns:
        bool: True if the string matches the domain pattern, False otherwise.
    """
    if domain and re.match(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", domain
    ):
        return True
    return False


def send_slack_notification(webhook_url: str, message: str) -> None:
    """
    Sends a message to a Slack channel using an incoming webhook.

    Args:
        webhook_url (str): The Slack incoming webhook URL.
        message (str): The message to send.
    """
    if not webhook_url:
        logger.warning("Slack webhook URL not configured. Skipping notification.")
        return
    try:
        payload = {"text": message}
        response = sync_client.post(webhook_url, json=payload)
        response.raise_for_status()
        logger.info("Successfully sent Slack notification.")
    except Exception as e:
        logger.error("Failed to send Slack notification: %s", e)
