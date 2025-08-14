import json
import re
from rich.console import Console
from rich.json import JSON

# Initialize a single console instance to be used by any module that imports this file.
console = Console()

def save_or_print_results(data: dict, output_file: str | None):
    """
    Handles the output of scan results.

    Saves the data to a JSON file if an output path is provided,
    otherwise prints it to the console in a formatted way using the rich library.

    Args:
        data (dict): The dictionary containing the scan results.
        output_file (str | None): The file path to save the JSON output.
                                  If None, prints to the console.
    """
    # Use standard json.dumps to create a string with proper formatting.
    # The default=str is a safeguard to handle data types that are not
    # natively JSON serializable, like datetime objects from the whois library.
    json_str = json.dumps(data, indent=4, ensure_ascii=False, default=str)
    
    if output_file:
        console.print(f" [cyan]>[/cyan] Saving results to [yellow]{output_file}[/yellow]...")
        try:
            # Open the file and write the formatted JSON string.
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(json_str)
            console.print(f"[bold green]Successfully saved to {output_file}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Error saving file:[/] {e}")
    else:
        # If no output file is specified, print the formatted JSON to the console.
        # The rich.json.JSON object handles syntax highlighting automatically.
        console.print(JSON(json_str))

def is_valid_domain(domain: str) -> bool:
    """Validates if the given string is a plausible domain name."""
    # This regex is a common pattern for domain validation. It checks for a basic structure
    # of characters, hyphens, and dots, ending with a TLD of 2-6 letters.
    if domain and re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", domain):
        return True
    return False