from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables.

    Environment variables override the default values defined here.
    During local development, values are normally loaded from the
    project's .env file.
    """

    # Application
    app_name: str = "Marketplace Identity Service"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"

    # Database
    database_url: str = (
        "postgresql+asyncpg://marketplace:marketplace"
        "@localhost:5433/marketplace_identity"
    )

    # Redis
    redis_url: str = "redis://localhost:6380/0"

    # JWT
    jwt_secret_key: str = "change-this-in-production"
    jwt_algorithm: str = "HS256"

    # Token expiration
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # Email verification
    email_verification_expire_minutes: int = 30

    # Password reset
    password_reset_expire_minutes: int = 30

    # Account protection
    max_failed_login_attempts: int = 5
    account_lock_minutes: int = 15

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """
    Return a cached application settings instance.

    Caching prevents the .env file from being parsed repeatedly.
    """
    return Settings()