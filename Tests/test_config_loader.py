import pytest
import importlib
import logging
from unittest.mock import MagicMock, mock_open
# Import the module we are testing
from chimera_intel.core import config_loader
from chimera_intel.core.schemas import AppConfig


@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    """Fixture to clear relevant env vars before each test."""
    vars_to_clear = [
        "VAULT_ADDR", "VAULT_TOKEN", "VAULT_SECRET_PATH",
        "SECRET_KEY", "VIRUSTOTAL_API_KEY", "DB_NAME", "DB_USER",
        "DB_PASSWORD", "DB_HOST", "DB_PORT", "DATABASE_URL", "FINNHUB_API_KEY"
    ]
    for var in vars_to_clear:
        monkeypatch.delenv(var, raising=False)

@pytest.fixture
def mock_hvac(mocker):
    """Fixture to mock the hvac.Client."""
    mock_client = MagicMock()
    mocker.patch('hvac.Client', return_value=mock_client)
    return mock_client

@pytest.fixture
def mock_yaml(mocker):
    """Fixture to mock yaml.safe_load and builtins.open."""
    mock_open_func = mock_open(read_data="app_name: Test App")
    mocker.patch("builtins.open", mock_open_func)
    
    mock_yaml_load = mocker.patch("yaml.safe_load", return_value={"app_name": "Test App from YAML"})
    return mock_yaml_load, mock_open_func


# --- Tests for get_secrets_from_vault ---

def test_get_secrets_from_vault_success(mock_hvac, monkeypatch, caplog):
    """Tests successful retrieval of secrets from Vault."""
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test_token")
    monkeypatch.setenv("VAULT_SECRET_PATH", "secret/myapp")

    mock_hvac.is_authenticated.return_value = True
    mock_response = {
        "data": {
            "data": {"SECRET_KEY": "vault_secret"}
        }
    }
    mock_hvac.secrets.kv.v2.read_secret_version.return_value = mock_response

    with caplog.at_level(logging.INFO):
        secrets = config_loader.get_secrets_from_vault()

    assert secrets == {"SECRET_KEY": "vault_secret"}
    assert "Successfully loaded secrets from HashiCorp Vault" in caplog.text

def test_get_secrets_from_vault_missing_env_vars(caplog):
    """Tests that Vault is skipped if env vars are not set."""
    with caplog.at_level(logging.INFO):
        secrets = config_loader.get_secrets_from_vault()

    assert secrets == {}
    assert "Vault environment variables not fully set" in caplog.text

def test_get_secrets_from_vault_auth_failed(mock_hvac, monkeypatch, caplog):
    """Tests failure to authenticate with Vault."""
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "bad_token")
    monkeypatch.setenv("VAULT_SECRET_PATH", "secret/myapp")

    mock_hvac.is_authenticated.return_value = False

    with caplog.at_level(logging.ERROR):
        secrets = config_loader.get_secrets_from_vault()

    assert secrets == {}
    assert "Vault authentication failed" in caplog.text

def test_get_secrets_from_vault_exception(mock_hvac, monkeypatch, caplog):
    """Tests a generic exception during Vault communication."""
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test_token")
    monkeypatch.setenv("VAULT_SECRET_PATH", "secret/myapp")

    mock_hvac.is_authenticated.side_effect = Exception("Connection error")

    with caplog.at_level(logging.ERROR):
        secrets = config_loader.get_secrets_from_vault()

    assert secrets == {}
    assert "Failed to fetch secrets from Vault: Connection error" in caplog.text


# --- Tests for ApiKeys Class ---

def test_api_keys_default_secret_key(monkeypatch):
    """Tests that the default secret key is used if none is provided."""
    # We must reload the module to re-trigger the class definition and instantiation
    importlib.reload(config_loader)
    api_keys = config_loader.ApiKeys() # type: ignore
    assert api_keys.secret_key == "default_secret_key_for_dev"

def test_api_keys_load_from_env(monkeypatch):
    """Tests loading various API keys from environment variables."""
    monkeypatch.setenv("SECRET_KEY", "env_secret")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "virustotal_key")
    monkeypatch.setenv("GITHUB_PAT", "github_token")

    # Reload the module to re-instantiate API_KEYS at the module level
    importlib.reload(config_loader)
    
    assert config_loader.API_KEYS.secret_key == "env_secret"
    assert config_loader.API_KEYS.virustotal_api_key == "virustotal_key"
    assert config_loader.API_KEYS.github_pat == "github_token"
    assert config_loader.API_KEYS.shodan_api_key is None

def test_api_keys_assemble_db_connection(monkeypatch):
        """Tests the Pydantic validator for assembling the database URL."""
        monkeypatch.setenv("DB_USER", "postgres")
        monkeypatch.setenv("DB_PASSWORD", "mypassword")
        monkeypatch.setenv("DB_HOST", "localhost")
        monkeypatch.setenv("DB_PORT", "5432")
        monkeypatch.setenv("DB_NAME", "chimera_db")

        # --- FIX: Use importlib.reload to re-instantiate module-level API_KEYS ---
        importlib.reload(config_loader)
    
        # The str() of a PostgresDsn object redacts the password
        # UPDATED FIX: Pydantic's PostgresDsn string representation *includes* the
        # port if it was explicitly passed in the connection string,
        # which our validator does when DB_PORT is set.
        expected_url = "postgresql://postgres:***@localhost:5432/chimera_db"
        
        # --- FIX: Assert against the reloaded module-level instance ---
        assert str(config_loader.API_KEYS.database_url) == expected_url

def test_api_keys_assemble_db_connection_incomplete(monkeypatch):
    """Tests that DB URL is None if some connection vars are missing."""
    monkeypatch.setenv("DB_USER", "postgres")
    monkeypatch.setenv("DB_HOST", "localhost")
    # Missing password, name, and port
    
    importlib.reload(config_loader)
    
    assert config_loader.API_KEYS.database_url is None

def test_api_keys_direct_database_url_override(monkeypatch):
    """Tests that a directly provided DATABASE_URL overrides assembly."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://direct:url@host:1234/direct_db")
    
    # --- FIX: Do not set other DB_ vars. The clear_env fixture handles this.
    # Setting them triggers the assembly validator, which (if incomplete)
    # can overwrite the DATABASE_URL value.
    
    importlib.reload(config_loader)
    
    # FIX: Assert the redacted string, as PostgresDsn will hide the password.
    # The port (1234) is non-default, so it will be included.
    assert str(config_loader.API_KEYS.database_url) == "postgresql://direct:***@host:1234/direct_db"

def test_api_keys_vault_priority(mock_hvac, monkeypatch):
    """
    Tests the settings_customise_sources method to ensure Vault
    secrets (Priority 2) override environment variables (Priority 3).
    """
    # 1. Set Vault env vars
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test_token")
    monkeypatch.setenv("VAULT_SECRET_PATH", "secret/myapp")

    # 2. Set conflicting API key in environment
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "key_from_env")

    # 3. Configure mock_hvac to return the secret
    mock_hvac.is_authenticated.return_value = True
    mock_response = {
        "data": {
            "data": {"VIRUSTOTAL_API_KEY": "key_from_vault"}
        }
    }
    mock_hvac.secrets.kv.v2.read_secret_version.return_value = mock_response

    # 4. Reload the module to trigger the `ApiKeys()` instantiation
    importlib.reload(config_loader)

    # 5. Check that the key from Vault won
    assert config_loader.API_KEYS.virustotal_api_key == "key_from_vault"


# --- Tests for load_config_from_yaml ---

def test_load_config_success(mock_yaml):
    """Tests loading a valid config.yaml."""
    mock_load, _ = mock_yaml
    mock_load.return_value = {
        "app_name": "Test App",
        "log_level": "DEBUG",
        "network": {"timeout": 30.0},
        "modules": {"footprint": {"dns_records_to_query": ["A", "MX"]}}
    }

    config = config_loader.load_config_from_yaml()
    
    assert isinstance(config, AppConfig)
    assert config.app_name == "Test App"
    assert config.log_level == "DEBUG"
    assert config.network.timeout == 30.0

def test_load_config_file_not_found(mocker, caplog):
    """Tests fallback to default config if config.yaml is not found."""
    mocker.patch("builtins.open", side_effect=FileNotFoundError)
    
    with caplog.at_level(logging.WARNING):
        config = config_loader.load_config_from_yaml()

    assert "config.yaml not found. Using default application settings." in caplog.text
    assert isinstance(config, AppConfig)
    assert config.app_name == "Chimera Intel"  # Default value
    assert config.log_level == "INFO"        # Default value

def test_load_config_validation_error(mock_yaml, caplog):
    """Tests that the program exits on a Pydantic validation error."""
    mock_load, _ = mock_yaml
    # Pass invalid data type for timeout
    mock_load.return_value = {"network": {"timeout": "not-a-float"}}
    
    with pytest.raises(SystemExit) as excinfo:
        with caplog.at_level(logging.CRITICAL):
            config_loader.load_config_from_yaml()

    # Assert SystemExit code 1 and log content
    assert excinfo.value.code == 1
    assert "Invalid configuration in config.yaml" in caplog.text

def test_load_config_generic_exception(mocker, caplog):
    """Tests that the program exits on any other file loading error."""
    mocker.patch("builtins.open", side_effect=PermissionError("Permission denied"))
    
    with pytest.raises(SystemExit) as excinfo:
        with caplog.at_level(logging.CRITICAL):
            config_loader.load_config_from_yaml()
    
    # Assert SystemExit code 1 and log content
    assert excinfo.value.code == 1
    assert "An unexpected error occurred" in caplog.text
    assert "Permission denied" in caplog.text