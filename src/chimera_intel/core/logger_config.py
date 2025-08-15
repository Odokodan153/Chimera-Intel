import logging
from logging.handlers import RotatingFileHandler
from rich.logging import RichHandler

def setup_logging():
    """
    Configures a centralized logging system for the entire application.

    This setup directs logs to two places:
    1. The console, with beautiful, color-coded formatting provided by RichHandler.
       Only messages of level INFO and higher will be shown here.
    2. A rotating log file ('chimera_intel.log'), which captures everything
       from the DEBUG level upwards for detailed analysis.
    """
    # Create the top-level logger
    log = logging.getLogger("chimera_intel")
    log.setLevel(logging.DEBUG) # Capture everything at the root level

    # Prevent logs from being passed up to the root logger's handlers
    log.propagate = False

    # --- Console Handler (for pretty, user-facing output) ---
    rich_handler = RichHandler(
        level=logging.INFO,
        show_path=False, # Don't show file path for cleaner output
        rich_tracebacks=True,
        markup=True
    )

    # --- File Handler (for detailed, persistent logs) ---
    # Use RotatingFileHandler to keep log files from growing indefinitely.
    file_handler = RotatingFileHandler(
        "chimera_intel.log",
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=2, # Keep 2 old log files
        encoding='utf-8'
    )
    # The file log should be very detailed.
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    # Add the handlers to the logger, but only if they haven't been added before
    if not log.handlers:
        log.addHandler(rich_handler)
        log.addHandler(file_handler)