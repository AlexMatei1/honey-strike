"""Typed application configuration loaded from environment / .env files."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- app -----------------------------------------------------------------
    app_env: Literal["development", "production"] = "development"
    log_level: str = "INFO"
    domain: str = "localhost"

    # ---- database ------------------------------------------------------------
    database_url: str = Field(
        default="postgresql+asyncpg://honeystrike:change-me-honeystrike@postgres:5432/honeystrike"
    )

    # ---- redis ---------------------------------------------------------------
    redis_url: str = "redis://redis:6379/0"
    redis_stream: str = "honeystrike:events"
    redis_stream_maxlen: int = 100_000

    # ---- auth ----------------------------------------------------------------
    secret_key: str = "replace-with-64-hex-chars"
    jwt_algorithm: Literal["RS256", "HS256"] = "RS256"
    jwt_access_ttl_seconds: int = 3600
    jwt_refresh_ttl_seconds: int = 7 * 24 * 3600
    admin_username: str = "admin"
    admin_password: str = "change-me-strong-password"
    # Self-service account creation. On for dev/demo so visitors get their own
    # login + profile; set ALLOW_REGISTRATION=false for a locked-down capture
    # deployment where only the seeded admin should exist.
    allow_registration: bool = True

    # ---- workers -------------------------------------------------------------
    worker_concurrency: int = 4
    session_max_duration_seconds: int = 300
    ftp_session_max_duration_seconds: int = 120

    # ---- alerting ------------------------------------------------------------
    alert_threshold_medium: int = 30
    alert_threshold_high: int = 60
    alert_threshold_critical: int = 80
    alert_cooldown_seconds: int = 1800
    telegram_token: str = ""
    telegram_chat_id: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "honeystrike@example.com"
    smtp_to: str = ""
    slack_webhook_url: str = ""
    discord_webhook_url: str = ""

    # ---- intel APIs ----------------------------------------------------------
    abuseipdb_key: str = ""
    abuseipdb_cache_ttl_seconds: int = 6 * 3600
    maxmind_account_id: str = ""
    maxmind_license_key: str = ""
    maxmind_db_dir: str = "/maxmind"

    # ---- reports -------------------------------------------------------------
    reports_dir: str = "/reports"
    reports_retention_days: int = 180
    report_auto_trigger_score: int = 60


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
