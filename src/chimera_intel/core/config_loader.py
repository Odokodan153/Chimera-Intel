import yaml
import os
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional
from rich.console import Console

# This module is now self-contained and handles loading all configurations.

# Initialize a console for any potential warnings or errors
console = Console()

# --- Pydantic Model for API Keys ---
# This class uses pydantic-settings to automatically read variables from your .env file.
# It provides type hints and default values, ensuring your keys are loaded correctly.
class ApiKeys(BaseSettings):
    """
    Loads all required API keys from environment variables (.env file).
    """
    # Offensive Intelligence Keys
    virustotal_api_key: Optional[str] = Field(None, alias="VIRUSTOTAL_API_KEY")
    builtwith_api_key: Optional[str] = Field(None, alias="BUILTWITH_API_KEY")
    wappalyzer_api_key: Optional[str] = Field(None, alias="WAPPALYZER_API_KEY")
    similarweb_api_key: Optional[str] = Field(None, alias="SIMILARWEB_API_KEY")
    gnews_api_key: Optional[str] = Field(None, alias="GNEWS_API_KEY")
    securitytrails_api_key: Optional[str] = Field(None, alias="SECURITYTRAILS_API_KEY")
    
    # Defensive Counter-Intelligence Keys
    hibp_api_key: Optional[str] = Field(None, alias="HIBP_API_KEY")
    github_pat: Optional[str] = Field(None, alias="GITHUB_PAT")
    shodan_api_key: Optional[str] = Field(None, alias="SHODAN_API_KEY")
    mobsf_api_key: Optional[str] = Field(None, alias="MOBSF_API_KEY")

    # AI Core Keys
    google_api_key: Optional[str] = Field(None, alias="GOOGLE_API_KEY")
    
    class Config:
        # Tell pydantic-settings to look for a .env file
        env_file = ".env"
        env_file_encoding = "utf-8"

def load_config_from_yaml() -> dict:
    """
    Loads the application configuration from config.yaml.
    This function will be updated later to use Pydantic models as well.

    Returns:
        dict: A dictionary containing the application's configuration.
    """
    try:
        with open("config.yaml", 'r') as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        console.print("[bold yellow]Warning:[/] config.yaml not found. Using default settings.")
        # Return a default structure if the file is missing
        return {
            "network": {"timeout": 20.0},
            "modules": {"footprint": {"dns_records_to_query": ["A", "MX"]}}
        }
    except Exception as e:
        console.print(f"[bold red]Error loading config.yaml:[/] {e}")
        return {}

# --- Single Source of Truth ---
# Load the configurations once when the module is first imported.
# Any other module can now simply `from .config_loader import CONFIG, API_KEYS`
# to get access to all validated configurations and secrets.
CONFIG = load_config_from_yaml()
API_KEYS = ApiKeys()