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

# FIX: Removed PostgresDsn import
from pydantic import Field, ValidationError, field_validator
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

    # --- All other API keys ---

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
    alpha_vantage_api_key: Optional[str] = Field(None, alias="ALPHA_VANTAGE_API_KEY")
    easypost_api_key: Optional[str] = Field(None, alias="EASYPOST_API_KEY")
    finnhub_api_key: Optional[str] = Field(None, alias="FINNHUB_API_KEY")
    wigle_api_key: Optional[str] = Field(None, alias="WIGLE_API_KEY")
    kickstarter_api_key: Optional[str] = os.getenv("KICKSTARTER_API_KEY")

    # Maritime & Shipping Intelligence Keys

    aisstream_api_key: Optional[str] = Field(None, alias="AISSTREAM_API_KEY")

    # Weather & Environmental Intelligence Keys

    openweathermap_api_key: Optional[str] = Field(None, alias="OPENWEATHERMAP_API_KEY")

    # ---: MLINT (Money Laundering Intel) Keys ---
    
    # Basic AML/UBO/Sanctions
    aml_api_key: Optional[str] = Field(None, alias="AML_API_KEY")
    world_check_api_key: Optional[str] = Field(None, alias="WORLD_CHECK_API_KEY")
    
    # On-chain Crypto Analytics
    chain_api_key: Optional[str] = Field(None, alias="CHAIN_API_KEY") # Generic
    chainalysis_api_key: Optional[str] = Field(None, alias="CHAINALYSIS_API_KEY")
    trm_labs_api_key: Optional[str] = Field(None, alias="TRM_LABS_API_KEY")
    nansen_api_key: Optional[str] = Field(None, alias="NANSEN_API_KEY")

    # Global Banking
    swift_gpi_api_key: Optional[str] = Field(None, alias="SWIFT_GPI_API_KEY")

    # ---: Database Credentials ---

    db_name: Optional[str] = Field(None, alias="DB_NAME")
    db_user: Optional[str] = Field(None, alias="DB_USER")
    db_password: Optional[str] = Field(None, alias="DB_PASSWORD")
    db_host: Optional[str] = Field(None, alias="DB_HOST")
    db_port: Optional[int] = Field(5432, alias="DB_PORT")

    # ---: Graph Database Credentials ---

    neo4j_uri: Optional[str] = Field(None, alias="NEO4J_URI")
    neo4j_user: Optional[str] = Field(None, alias="NEO4J_USER")
    neo4j_password: Optional[str] = Field(None, alias="NEO4J_PASSWORD")
    
    # ---: Streaming (Kafka) Credentials ---
    
    kafka_bootstrap_servers: Optional[str] = Field(None, alias="KAFKA_BOOTSTRAP_SERVERS")
    kafka_topic_transactions: Optional[str] = Field("mlint_transactions", alias="KAFKA_TOPIC_TRANSACTIONS")
    kafka_topic_alerts: Optional[str] = Field("mlint_alerts", alias="KAFKA_TOPIC_ALERTS")
    kafka_consumer_group: Optional[str] = Field("mlint_processor_group", alias="KAFKA_CONSUMER_GROUP")

    # FIX: Change type hint from Optional[PostgresDsn] to Optional[str]
    database_url: Optional[str] = None

    @field_validator("database_url", mode="before")
    def assemble_db_connection(cls, v: Optional[str], values: Any) -> Any:
        if isinstance(v, str):
            return v

        # FIX: Rely on environment variables (raw strings) and use an explicit default for port
        # This is more robust in a `mode="before"` validator where field parsing isn't guaranteed
        db_host = os.getenv("DB_HOST")
        db_user = os.getenv("DB_USER")
        db_password = os.getenv("DB_PASSWORD")
        db_name = os.getenv("DB_NAME")

        # Get DB_PORT as a string from environment, or use the field default "5432" as fallback
        # values.data.get('DB_PORT') is for the alias, os.getenv('DB_PORT') is the raw env var.
        db_port_raw = values.data.get("DB_PORT") or os.getenv("DB_PORT")

        # Fallback to the default value (5432) as a string if no env value is found
        db_port = str(db_port_raw) if db_port_raw else str(5432)

        if all(
            [db_host, db_user, db_password, db_name, db_port]
        ):  # FIX: Added db_port to the check
            # Always return a raw string to prevent PostgresDsn from redacting or truncating the database name
            assembled = (
                f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
            )
            return assembled
        return v

    class Config:
        """Pydantic-settings configuration."""

        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # Ignore extra fields from Vault that don't match

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
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
            dotenv_settings,
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
API_KEYS = ApiKeys()  # type: ignore

# --- MLINT Specific Configurations ---

# Load MLINT API URLs from .env
MLINT_AML_API_URL = os.getenv("MLINT_AML_API_URL", "https://api.amlcheck.com/v1/entity-screen")
MLINT_CHAIN_API_URL = os.getenv("MLINT_CHAIN_API_URL", "https://api.chainanalysis.com/v1/address-screen")

# Load configurable risk weights from .env
try:
    MLINT_RISK_WEIGHTS = {
        "fatf_black_list": int(os.getenv("MLINT_RISK_WEIGHT_FATF_BLACK_LIST", 50)),
        "fatf_grey_list": int(os.getenv("MLINT_RISK_WEIGHT_FATF_GREY_LIST", 25)),
        "pep_link": int(os.getenv("MLINT_RISK_WEIGHT_PEP_LINK", 30)),
        "sanctions_hit": int(os.getenv("MLINT_RISK_WEIGHT_SANCTIONS_HIT", 70)),
        "adverse_media": int(os.getenv("MLINT_RISK_WEIGHT_ADVERSE_MEDIA", 5)),
        "shell_indicator": int(os.getenv("MLINT_RISK_WEIGHT_SHELL_INDICATOR", 10)),
    }
except ValueError as e:
    logger.warning(f"Could not parse MLINT_RISK_WEIGHTS from .env. Using defaults. Error: {e}")
    MLINT_RISK_WEIGHTS = {
        "fatf_black_list": 50, "fatf_grey_list": 25, "pep_link": 30,
        "sanctions_hit": 70, "adverse_media": 5, "shell_indicator": 10,
    }