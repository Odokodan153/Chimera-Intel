import yaml
from pydantic_settings import BaseSettings
from pydantic import Field, ValidationError
from typing import Optional
import logging

# --- CORRECTED Absolute Imports ---
from .schemas import AppConfig

# Get a logger instance for this specific file
logger = logging.getLogger(__name__)


class ApiKeys(BaseSettings):
    """
    Loads all required API keys from environment variables found in a .env file.

    This class uses pydantic-settings to automatically read, validate, and type-cast
    environment variables. It provides a single, reliable object for accessing secrets
    throughout the application.
    """
    # Offensive Intelligence Keys
    virustotal_api_key: Optional[str] = Field(None, alias="VIRUSTOTAL_API_KEY")
    builtwith_api_key: Optional[str] = Field(None, alias="BUILTWITH_API_KEY")
    wappalyzer_api_key: Optional[str] = Field(None, alias="WAPPALYZER_API_KEY")
    similarweb_api_key: Optional[str] = Field(None, alias="SIMILARWEB_API_KEY")
    gnews_api_key: Optional[str] = Field(None, alias="GNEWS_API_KEY")
    
    # Defensive Counter-Intelligence Keys
    hibp_api_key: Optional[str] = Field(None, alias="HIBP_API_KEY")
    github_pat: Optional[str] = Field(None, alias="GITHUB_PAT")
    shodan_api_key: Optional[str] = Field(None, alias="SHODAN_API_KEY")
    mobsf_api_key: Optional[str] = Field(None, alias="MOBSF_API_KEY")

    # AI Core Keys
    google_api_key: Optional[str] = Field(None, alias="GOOGLE_API_KEY")
    
    # Notification Keys
    slack_webhook_url: Optional[str] = Field(None, alias="SLACK_WEBHOOK_URL")
    
    class Config:
        """Pydantic-settings configuration."""
        env_file = ".env"
        env_file_encoding = "utf-8"


def load_config_from_yaml() -> AppConfig:
    """
    Loads and validates the application configuration from 'config.yaml' using a Pydantic model.

    If the file is not found, it returns a default AppConfig instance. If the file
    is malformed, it reports an error and exits the program.

    Returns:
        AppConfig: A validated Pydantic object representing the application's configuration.
    """
    try:
        with open("config.yaml", 'r') as f:
            config_data = yaml.safe_load(f)
        return AppConfig(**config_data)
    except FileNotFoundError:
        logger.warning("config.yaml not found. Using default application settings.")
        return AppConfig.model_validate({})
    except ValidationError as e:
        logger.critical("Invalid configuration in config.yaml. Please check the structure. Error: %s", e)
        exit(1)
    except Exception as e:
        logger.critical("An unexpected error occurred while loading config.yaml: %s", e)
        exit(1)


# --- Single Source of Truth ---
# The configurations are loaded once when this module is first imported.
# Any other module can now simply `from .config_loader import CONFIG, API_KEYS`
# to get access to all validated configurations and secrets.
CONFIG = load_config_from_yaml()
API_KEYS = ApiKeys()