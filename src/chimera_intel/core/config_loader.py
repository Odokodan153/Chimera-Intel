"""
Configuration loader for the Chimera Intel application.

This module is responsible for loading all application configurations and secrets.
It follows a priority system for loading secrets:
1. HashiCorp Vault (for production)
2. Environment variables (can be populated by a .env file for development)

It also centralizes the creation of the SQLAlchemy database URL.
"""

import logging
import os
from typing import Any, Dict, Optional

import hvac
import yaml
from pydantic import Field, PostgresDsn, ValidationError
from pydantic_settings import BaseSettings

from .schemas import AppConfig

# Get a logger instance for this specific file


logger = logging.getLogger(__name__)


def get_secrets_from_vault() -> Dict[str, Any]:
    """
    Fetches secrets from a configured HashiCorp Vault instance.
    This is the recommended method for production environments.
    """
    try:
        vault_addr = os.getenv("VAULT_ADDR")
        vault_token = os.getenv("VAULT_TOKEN")
        vault_path = os.getenv("VAULT_SECRET_PATH")

        if not all([vault_addr, vault_token, vault_path]):
            logger.info(
                "Vault environment variables not fully set. Skipping Vault integration."
            )
            return {}
        client = hvac.Client(url=vault_addr, token=vault_token)
        if not client.is_authenticated():
            logger.error("Vault authentication failed. Please check your VAULT_TOKEN.")
            return {}
        response = client.secrets.kv.v2.read_secret_version(path=vault_path)
        secrets = response.get("data", {}).get("data", {})
        logger.info("Successfully loaded secrets from HashiCorp Vault.")
        return secrets
    except Exception as e:
        logger.error(f"Failed to fetch secrets from Vault: {e}")
        return {}


class ApiKeys(BaseSettings):
    """
    Loads all required API keys, database credentials, and other secrets.
    """

    # --- JWT Secret Key ---

    secret_key: str = Field("default_secret_key_for_dev", alias="SECRET_KEY")

    # --- Database Credentials ---

    db_user: str = Field("user", alias="DB_USER")
    db_password: str = Field("password", alias="DB_PASSWORD")
    db_host: str = Field("localhost", alias="DB_HOST")
    db_name: str = Field("chimera_intel", alias="DB_NAME")
    db_port: int = Field(5432, alias="DB_PORT")

    # --- SQLAlchemy Database URL (constructed automatically) ---

    database_url: Optional[PostgresDsn] = None

    # --- All other API keys ---

    virustotal_api_key: Optional[str] = Field(None, alias="VIRUSTOTAL_API_KEY")
    builtwith_api_key: Optional[str] = Field(None, alias="BUILTWITH_API_KEY")
    wappalyzer_api_key: Optional[str] = Field(None, alias="WAPPALYZER_API_KEY")
    similarweb_api_key: Optional[str] = Field(None, alias="SIMILARWEB_API_KEY")
    gnews_api_key: Optional[str] = Field(None, alias="GNEWS_API_KEY")
    hunter_api_key: Optional[str] = Field(None, alias="HUNTER_API_KEY")
    open_corporates_api_key: Optional[str] = Field(
        None, alias="OPEN_CORPORATES_API_KEY"
    )
    hibp_api_key: Optional[str] = Field(None, alias="HIBP_API_KEY")
    github_pat: Optional[str] = Field(None, alias="GITHUB_PAT")
    shodan_api_key: Optional[str] = Field(None, alias="SHODAN_API_KEY")
    mobsf_api_key: Optional[str] = Field(None, alias="MOBSF_API_KEY")
    vulners_api_key: Optional[str] = Field(None, alias="VULNERS_API_KEY")
    otx_api_key: Optional[str] = Field(None, alias="OTX_API_KEY")
    sec_api_io_key: Optional[str] = Field(None, alias="SEC_API_IO_KEY")
    sec_api_user_agent: Optional[str] = Field(None, alias="SEC_API_USER_AGENT")
    gemini_api_key: Optional[str] = Field(None, alias="GEMINI_API_KEY")
    cicd_webhook_url: Optional[str] = Field(None, alias="CICD_WEBHOOK_URL")
    cicd_auth_token: Optional[str] = Field(None, alias="CICD_AUTH_TOKEN")
    slack_webhook_url: Optional[str] = Field(None, alias="SLACK_WEBHOOK_URL")
    teams_webhook_url: Optional[str] = Field(None, alias="TEAMS_WEBHOOK_URL")
    aura_api_key: Optional[str] = Field(None, alias="AURA_API_KEY")
    lobbying_data_api_key: Optional[str] = Field(None, alias="LOBBYING_DATA_API_KEY")
    spycloud_api_key: Optional[str] = Field(None, alias="SPYCLOUD_API_KEY")
    etherscan_api_key: Optional[str] = Field(None, alias="ETHERSCAN_API_KEY")
    google_maps_api_key: Optional[str] = Field(None, alias="GOOGLE_MAPS_API_KEY")
    import_genius_api_key: Optional[str] = Field(None, alias="IMPORT_GENIUS_API_KEY")
    uspto_api_key: Optional[str] = Field(None, alias="USPTO_API_KEY")
    kaggle_api_key: Optional[str] = Field(None, alias="KAGGLE_API_KEY")
    courtlistener_api_key: Optional[str] = Field(None, alias="COURTLISTENER_API_KEY")
    twitter_bearer_token: Optional[str] = Field(None, alias="TWITTER_BEARER_TOKEN")
    youtube_api_key: Optional[str] = Field(None, alias="YOUTUBE_API_KEY")
    alpha_vantage_api_key: Optional[str] = Field(None, alias="ALPHA_VANTAGE_API_KEY")
    easypost_api_key: Optional[str] = Field(None, alias="EASYPOST_API_KEYUBE_API_KEY")
    aisstream_api_key: Optional[str] = Field(None, alias="AISSTREAM_API_KEY")
    openweathermap_api_key: Optional[str] = Field(None, alias="OPENWEATHERMAP_API_KEY")
    neo4j_uri: Optional[str] = Field(None, alias="NEO4J_URI")
    neo4j_user: Optional[str] = Field(None, alias="NEO4J_USER")
    neo4j_password: Optional[str] = Field(None, alias="NEO4J_PASSWORD")

    def __init__(self, **values: Any):
        super().__init__(**values)
        # Construct the database URL after loading all other values

        self.database_url = f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    class Config:
        """Pydantic-settings configuration."""

        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # Ignore extra fields from Vault that don't match

    @classmethod
    def settings_customise_sources(
        cls, settings_cls, init_settings, env_settings, file_secret_settings
    ):
        """
        Customizes the loading priority for settings.
        1. Values passed directly to the constructor.
        2. Secrets from HashiCorp Vault.
        3. Environment variables (including those from .env file).
        4. File-based secrets (not used here).
        """
        return (
            init_settings,
            get_secrets_from_vault,
            env_settings,
            file_secret_settings,
        )


def load_config_from_yaml() -> AppConfig:
    """
    Loads and validates the main application configuration from 'config.yaml'.
    """
    try:
        with open("config.yaml", "r") as f:
            config_data = yaml.safe_load(f)
        return AppConfig(**config_data)
    except FileNotFoundError:
        logger.warning("config.yaml not found. Using default application settings.")
        return AppConfig.model_validate({})
    except ValidationError as e:
        logger.critical(
            f"Invalid configuration in config.yaml. Please check the structure. Error: {e}"
        )
        exit(1)
    except Exception as e:
        logger.critical(f"An unexpected error occurred while loading config.yaml: {e}")
        exit(1)


# --- Single Source of Truth ---
# The configurations and secrets are loaded once when this module is first imported.
# Any other module can now simply `from .config_loader import CONFIG, API_KEYS`
# to get access to all validated configurations and secrets.


CONFIG = load_config_from_yaml()
API_KEYS = ApiKeys()
