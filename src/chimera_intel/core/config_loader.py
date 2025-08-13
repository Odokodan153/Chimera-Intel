import yaml
from rich.console import Console

console = Console()

def load_config() -> dict:
    """
    Loads the application configuration from config.yaml.

    Returns:
        dict: A dictionary containing the application's configuration.
    """
    try:
        with open("config.yaml", 'r') as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        console.print("[bold red]Error:[/] config.yaml not found. Using default settings.")
        return {}
    except Exception as e:
        console.print(f"[bold red]Error loading config.yaml:[/] {e}")
        return {}

# Load the config once when the module is imported so it's available to other modules
CONFIG = load_config()