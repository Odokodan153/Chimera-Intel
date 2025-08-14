import yaml
import os
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional
from rich.console import Console

# This module handles loading all configurations from both the .env file (for secrets)
# and the config.yaml file (for application settings).

console = Console()

# --- Pydantic Model for API Keys ---
class ApiKeys(BaseSettings):
    """
    Loads all required API keys from environment variables found in a .env file.

    This class uses pydantic-settings to automatically read, validate, and type-cast
    environment variables. It provides a single, reliable object for accessing secrets
    throughout the application. The `alias` in the `Field` function maps the
    environment variable name (e.g., VIRUSTOTAL_API_KEY) to the class attribute
    (e.g., virustotal_api_key).
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
        """Pydantic-settings configuration."""
        # Tell pydantic-settings to look for a .env file in the root directory.
        env_file = ".env"
        env_file_encoding = "utf-8"

def load_config_from_yaml() -> dict:
    """
    Loads the application configuration from the 'config.yaml' file.

    If the file is not found, it returns a default configuration structure to allow
    the application to run with baseline settings.

    Returns:
        dict: A dictionary containing the application's configuration.
    """
    try:
        with open("config.yaml", 'r') as f:
            config = yaml.safe_load(f)
        return config if isinstance(config, dict) else {}
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
# The configurations are loaded once when this module is first imported.
# Any other module can now simply `from .config_loader import CONFIG, API_KEYS`
# to get access to all validated configurations and secrets.
CONFIG = load_config_from_yaml()
API_KEYS = ApiKeys()