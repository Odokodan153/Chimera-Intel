"""
Configuration loader for the Chimera Intel application.

...
"""

import yaml
from pydantic_settings import BaseSettings
from pydantic import Field, ValidationError
from typing import Optional
import logging
from .schemas import AppConfig

# Get a logger instance for this specific file


logger = logging.getLogger(__name__)


class ApiKeys(BaseSettings):
    """
    Loads all required API keys from environment variables found in a .env file.

    ...
    """

    # Offensive Intelligence Keys

    virustotal_api_key: Optional[str] = Field(None, alias="VIRUSTOTAL_API_KEY")
    builtwith_api_key: Optional[str] = Field(None, alias="BUILTWITH_API_KEY")
    wappalyzer_api_key: Optional[str] = Field(None, alias="WAPPALYZER_API_KEY")
    similarweb_api_key: Optional[str] = Field(None, alias="SIMILARWEB_API_KEY")
    gnews_api_key: Optional[str] = Field(None, alias="GNEWS_API_KEY")
    hunter_api_key: Optional[str] = Field(None, alias="HUNTER_API_KEY")
    open_corporates_api_key: Optional[str] = Field(
        None, alias="OPEN_CORPORATES_API_KEY"
    )

    # Defensive Counter-Intelligence Keys

    hibp_api_key: Optional[str] = Field(None, alias="HIBP_API_KEY")
    github_pat: Optional[str] = Field(None, alias="GITHUB_PAT")
    shodan_api_key: Optional[str] = Field(None, alias="SHODAN_API_KEY")
    mobsf_api_key: Optional[str] = Field(None, alias="MOBSF_API_KEY")
    vulners_api_key: Optional[str] = Field(None, alias="VULNERS_API_KEY")
    otx_api_key: Optional[str] = Field(None, alias="OTX_API_KEY")
    sec_api_io_key: Optional[str] = Field(None, alias="SEC_API_IO_KEY")
    sec_api_user_agent: Optional[str] = Field(None, alias="SEC_API_USER_AGENT")

    # AI Core Keys

    google_api_key: Optional[str] = Field(None, alias="GOOGLE_API_KEY")

    # MLOps & Automation Keys (ADDED)

    cicd_webhook_url: Optional[str] = Field(None, alias="CICD_WEBHOOK_URL")
    cicd_auth_token: Optional[str] = Field(None, alias="CICD_AUTH_TOKEN")

    # Notification Keys

    slack_webhook_url: Optional[str] = Field(None, alias="SLACK_WEBHOOK_URL")
    teams_webhook_url: Optional[str] = Field(None, alias="TEAMS_WEBHOOK_URL")

    # Corporate & Strategic Intelligence Keys

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
    alpha_vantage_api_key:Optional[str] = Field(None, alias="ALPHA_VANTAGE_API_KEY")
    easypost_api_key:Optional[str] = Field(None, alias="EASYPOST_API_KEYUBE_API_KEY")

    # Maritime & Shipping Intelligence Keys

    aisstream_api_key: Optional[str] = Field(None, alias="AISSTREAM_API_KEY")

    # Weather & Environmental Intelligence Keys

    openweathermap_api_key: Optional[str] = Field(None, alias="OPENWEATHERMAP_API_KEY")

    # ---: Database Credentials ---

    db_name: Optional[str] = Field(None, alias="DB_NAME")
    db_user: Optional[str] = Field(None, alias="DB_USER")
    db_password: Optional[str] = Field(None, alias="DB_PASSWORD")
    db_host: Optional[str] = Field(None, alias="DB_HOST")

    # ---: Graph Database Credentials ---

    neo4j_uri: Optional[str] = Field(None, alias="NEO4J_URI")
    neo4j_user: Optional[str] = Field(None, alias="NEO4J_USER")
    neo4j_password: Optional[str] = Field(None, alias="NEO4J_PASSWORD")

    class Config:
        """Pydantic-settings configuration."""

        env_file = ".env"
        env_file_encoding = "utf-8"


def load_config_from_yaml() -> AppConfig:
    """
    Loads and validates the application configuration from 'config.yaml' using a Pydantic model.

    ...
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
            "Invalid configuration in config.yaml. Please check the structure. Error: %s",
            e,
        )
        exit(1)
    except Exception as e:
        logger.critical("An unexpected error occurred while loading config.yaml: %s", e)
        exit(1)


# --- Single Source of Truth ---
# The configurations are loaded once when this module is first imported.
# Any other module can now simply `from .config_loader import CONFIG, API_KEYS`
# to get access to all validated configurations and secrets.


CONFIG = load_config_from_yaml()
API_KEYS = ApiKeys()  # type: ignore[call-arg]
