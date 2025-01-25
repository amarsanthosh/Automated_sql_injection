import configparser
import os

def load_config(config_file="config/config.ini"):
    if not os.path.exists(config_file):
        print(f"Configuration file {config_file} not found.")
        return None

    config = configparser.ConfigParser()
    config.read(config_file)

    settings = {
        "default_timeout": config.getint("settings", "default_timeout", fallback=10),
        "user_agent": config.get("settings", "user_agent", fallback="MySQLmap/1.0"),
        "max_retries": config.getint("settings", "max_retries", fallback=3),
    }
    return settings
