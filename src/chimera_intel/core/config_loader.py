import yaml
import os
from rich.console import Console
from dotenv import load_dotenv

# Load environment variables from the .env file at the beginning
load_dotenv()
console = Console()

def load_config_from_yaml() -> dict:
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
        console.print("[bold yellow]Warning:[/] config.yaml not found. Using default settings.")
        return {}
    except Exception as e:
        console.print(f"[bold red]Error loading config.yaml:[/] {e}")
        return {}

def load_api_keys_from_env() -> dict:
    """
    Loads all required API keys from environment variables (.env file).

    Returns:
        dict: A dictionary containing all the API keys for the various services.
    """
    keys = {
        # Offensive Intelligence
        "virustotal": os.getenv("VIRUSTOTAL_API_KEY"),
        "builtwith": os.getenv("BUILTWITH_API_KEY"),
        "wappalyzer": os.getenv("WAPPALYZER_API_KEY"),
        "similarweb": os.getenv("SIMILARWEB_API_KEY"),
        "gnews": os.getenv("GNEWS_API_KEY"),
        "securitytrails": os.getenv("SECURITYTRAILS_API_KEY"),
        
        # Defensive Counter-Intelligence
        "hibp": os.getenv("HIBP_API_KEY"),
        "github": os.getenv("GITHUB_PAT"),
        "shodan": os.getenv("SHODAN_API_KEY"),
        "mobsf": os.getenv("MOBSF_API_KEY"),

        # AI Core
        "google_ai": os.getenv("GOOGLE_API_KEY")
    }
    return keys

# Load configs once when the module is imported so they are available to other modules
CONFIG = load_config_from_yaml()
API_KEYS = load_api_keys_from_env()