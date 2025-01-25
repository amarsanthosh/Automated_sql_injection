import logging

# Set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Function to log messages (can be extended with different log levels)
def log_message(message, level="info"):
    if level == "info":
        logger.info(message)
    elif level == "warning":
        logger.warning(message)
    elif level == "error":
        logger.error(message)
    elif level == "debug":
        logger.debug(message)
    else:
        logger.info(message)

# Function to validate URL format
def validate_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        log_message(f"Invalid URL format: {url}", level="error")
        return False
    return True

# Function to handle errors
def handle_error(error_message):
    log_message(f"Error: {error_message}", level="error")
    # Additional logic for error handling can be added here (e.g., retry mechanism)
