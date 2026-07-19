import logging
import sys

def setup_logging(
    level: int = logging.INFO,
    log_format: str = "%(asctime)s - %(levelname)s - %(filename)s:%(funcName)s - %(message)s",
    log_file: str = None
) -> None:
    """
    Configure logging for the entire package.
    
    Args:
        level: Logging level (e.g., logging.INFO)
        log_format: Format string for log messages, including filename and function
        log_file: Optional file to write logs (None for console only)
    """
    # Create formatter
    formatter = logging.Formatter(log_format)
    
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers = [file_handler]
    else:
        # Create console handler if no log file is specified
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        handlers = [console_handler]

    # Configure root logger
    logging.basicConfig(
        level=level,
        handlers=handlers
    )
    
    # Ensure no duplicate handlers
    root = logging.getLogger()
    root.handlers = handlers