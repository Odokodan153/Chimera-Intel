import logging
import logging.config
import os
import yaml
from pythonjsonlogger import jsonlogger


def setup_logging(
    default_path="logging.yaml", default_level=logging.INFO, env_key="LOG_CFG"
):
    """Setup logging configuration"""
    path = os.getenv(env_key, default_path)
    if os.path.exists(path):
        with open(path, "rt") as f:
            config = yaml.safe_load(f.read())
        logging.config.dictConfig(config)
    else:
        # Basic config with JSON formatter for production environments

        log_handler = logging.StreamHandler()
        formatter = jsonlogger.JsonFormatter(
            "%(asctime)s %(name)s %(levelname)s %(message)s"
        )
        log_handler.setFormatter(formatter)

        logging.basicConfig(level=default_level, handlers=[log_handler])
        logging.info("Using basic logging configuration with JSON output.")
