import os

DEBUG = os.environ.get("DEBUG", "0") == "1"
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///local.db")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
