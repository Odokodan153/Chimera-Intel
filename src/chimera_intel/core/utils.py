import json
import re
from rich.console import Console
from rich.json import JSON
from typing import Dict, Any

# Initialize a single console instance to be used by any module that imports this file.
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
    # The default=str is a safeguard to handle data types that are not
    # natively JSON serializable, like datetime objects.
    json_str = json.dumps(data, indent=4, ensure_ascii=False, default=str)
    
    if output_file:
        console.print(f" [cyan]>[/cyan] Saving results to [yellow]{output_file}[/yellow]...")
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(json_str)
            console.print(f"[bold green]Successfully saved to {output_file}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Error saving file:[/] {e}")
    else:
        # The rich.json.JSON object handles syntax highlighting automatically.
        console.print(JSON(json_str))

def is_valid_domain(domain: str) -> bool:
    """
    Validates if the given string is a plausible domain name using a regular expression.

    Args:
        domain (str): The string to validate as a domain.

    Returns:
        bool: True if the string matches the domain pattern, False otherwise.
    """
    if domain and re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", domain):
        return True
    return False