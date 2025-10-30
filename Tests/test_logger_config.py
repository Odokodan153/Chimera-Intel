from unittest.mock import patch
import logging

# Import the function to be tested
from src.chimera_intel.core.logger_config import setup_logging


@patch("src.chimera_intel.core.logger_config.os.path.exists", return_value=False)
def test_setup_logging_basic_config(mock_path_exists):
    """
    Test that logging levels are set correctly using the basic
    fallback configuration (when logging.yaml is not found).
    """
    # Reset logging to default state
    logging.shutdown()
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # Call the setup function
    setup_logging()

    # Check that os.path.exists was called
    mock_path_exists.assert_called_with("logging.yaml")

    # Check that the root logger level is set to the default (INFO)
    assert logging.getLogger().getEffectiveLevel() == logging.INFO

    # Check that httpx logger level also inherits INFO
    assert logging.getLogger("httpx").getEffectiveLevel() == logging.INFO

    # Check that our main logger also inherits INFO
    assert logging.getLogger("chimera_intel").getEffectiveLevel() == logging.INFO

    # Check that at least one handler is added
    assert len(logging.getLogger().handlers) > 0

    # Check that the handler is a StreamHandler
    assert isinstance(logging.getLogger().handlers[0], logging.StreamHandler)
