import yaml
from pydantic_settings import BaseSettings
from pydantic import Field, ValidationError
from typing import Optional
from rich.console import Console

# --- CORRECTED Absolute Imports ---
# CHANGE: Import the Pydantic models for the config file
from .schemas import AppConfig

console = Console()

# ... (ApiKeys class remains unchanged) ...
class ApiKeys(BaseSettings):
    """Loads all required API keys from environment variables found in a .env file."""
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
        env_file = ".env"
        env_file_encoding = "utf-8"


def load_config_from_yaml() -> AppConfig:
    """
    Loads and validates the application configuration from 'config.yaml' using a Pydantic model.

    If the file is not found, it returns a default AppConfig instance. If the file
    is malformed, it reports an error and exits.

    Returns:
        AppConfig: A validated Pydantic object representing the application's configuration.
    """
    try:
        with open("config.yaml", 'r') as f:
            config_data = yaml.safe_load(f)
        # --- CHANGE: Validate the loaded dict against the AppConfig model ---
        return AppConfig(**config_data)
    except FileNotFoundError:
        console.print("[bold yellow]Warning:[/] config.yaml not found. Using default settings.")
        # Return a default instance of the config model
        return AppConfig.model_validate({})
    # --- CHANGE: Catch validation errors from Pydantic ---
    except ValidationError as e:
        console.print(f"[bold red]Error in config.yaml:[/] Invalid configuration. {e}")
        exit(1) # Exit the program because the config is broken
    except Exception as e:
        console.print(f"[bold red]Error loading config.yaml:[/] {e}")
        exit(1)


# --- Single Source of Truth ---
# The CONFIG variable is now a type-safe Pydantic object.
CONFIG = load_config_from_yaml()
API_KEYS = ApiKeys()