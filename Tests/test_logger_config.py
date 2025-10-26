import pytest
from unittest.mock import patch, MagicMock
import logging

# Import the function to be tested
from src.chimera_intel.core.logger_config import setup_logging

def test_setup_logging_levels():
    """Test that logging levels are set correctly."""
    # Reset logging to default state
    logging.shutdown()
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    # Call the setup function
    setup_logging()
    
    # Check that the root logger level is set
    assert logging.getLogger().getEffectiveLevel() == logging.DEBUG
    
    # Check that httpx logger level is set
    assert logging.getLogger("httpx").getEffectiveLevel() == logging.WARNING
    
    # Check that our main logger is DEBUG
    assert logging.getLogger("chimera_intel").getEffectiveLevel() == logging.DEBUG
    
    # Check that at least one handler is added
    assert len(logging.getLogger().handlers) > 0

@patch("src.chimera_intel.core.logger_config.setup_logging")
@patch("logging.info")
def test_main_block(mock_log_info, mock_setup_logging):
    """Test the __main__ block execution."""
    # This uses runpy to execute the module as if it were the main script
    import runpy

    with patch.dict("sys.modules", {"__main__": MagicMock()}):
        runpy.run_module("src.chimera_intel.core.logger_config", run_name="__main__")

    # Check that setup_logging was called
    mock_setup_logging.assert_called_once()
    
    # Check that the log messages were emitted
    assert mock_log_info.call_count == 5
    mock_log_info.assert_any_call("This is a debug message.")