import os
import warnings

from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_ENCRYPTION_KEY = "dGhpc2lzYXZhbGlkZmVybmV0a2V5Zm9yZGV2ZWxvcG1lbnQ="
_DEFAULT_SECRET_KEY = "default-jwt-secret"


class Settings(BaseSettings):
    """Application settings.

    Only handles the encryption key for sensitive data in SQLite.
    All other configuration is stored in the database.
    """

    # Core settings
    ENCRYPTION_KEY: str = _DEFAULT_ENCRYPTION_KEY  # Override via env var in production
    SECRET_KEY: str = _DEFAULT_SECRET_KEY  # Override via env var in production

    # Database settings
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/app.db"  # Relative path for development/testing
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


# Create global settings instance
settings = Settings()

# Warn if insecure defaults are in use outside of testing
if os.environ.get("TESTING") != "1":
    if settings.SECRET_KEY == _DEFAULT_SECRET_KEY:
        warnings.warn(
            "Using default SECRET_KEY. Set the SECRET_KEY environment variable for production.",
            stacklevel=1,
        )
    if settings.ENCRYPTION_KEY == _DEFAULT_ENCRYPTION_KEY:
        warnings.warn(
            "Using default ENCRYPTION_KEY. Set the ENCRYPTION_KEY environment variable for production.",
            stacklevel=1,
        )
