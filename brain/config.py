"""
LogClaw Brain — Configuration
config.py — Settings, environment variables, .env file loading

Author  : Rayyan Umair
Date    : 2026-05-12
Purpose : Centralised configuration for the LogClaw brain. All
          settings are read from environment variables with sensible
          defaults. Supports .env file for local development.
          Every setting is documented. Nothing is hardcoded anywhere
          else in the codebase — always import from here.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/LogClaw

"Technology evolves quickly. Responsibility does not."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import os
from pathlib import Path
from typing import List, Optional

# ── Third Party ───────────────────────────────────────────────────────────────
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator

# ── Base Paths ────────────────────────────────────────────────────────────────

BRAIN_DIR   = Path(__file__).parent
PROJECT_DIR = BRAIN_DIR.parent
DATA_DIR    = PROJECT_DIR / "data"
RULES_DIR   = PROJECT_DIR / "rules"
LOGS_DIR    = PROJECT_DIR / "logs"

# Create directories if they don't exist
DATA_DIR.mkdir(exist_ok=True)
RULES_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
(RULES_DIR / "builtin").mkdir(exist_ok=True)
(RULES_DIR / "community").mkdir(exist_ok=True)


# ── Settings ──────────────────────────────────────────────────────────────────

class Settings(BaseSettings):
    """
    All LogClaw Brain configuration.
    Values are loaded from environment variables or .env file.
    Defaults are production-safe and work out of the box.
    """

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ───────────────────────────────────────────────────────────

    app_name: str = Field(
        default="LogClaw Brain",
        description="Application name shown in logs and API responses",
    )
    app_version: str = Field(
        default="1.0.0",
        description="Application version",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level: DEBUG, INFO, WARNING, ERROR",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode — verbose logging, auto-reload",
    )

    # ── Server ────────────────────────────────────────────────────────────────

    host: str = Field(
        default="0.0.0.0",
        description="Host to bind the FastAPI server",
    )
    port: int = Field(
        default=8000,
        description="Port to bind the FastAPI server",
    )

    # ── ZeroMQ ────────────────────────────────────────────────────────────────

    zmq_address: str = Field(
        default="tcp://127.0.0.1:5555",
        description="ZeroMQ address to subscribe to — must match harvester --zmq flag",
    )
    zmq_topic: str = Field(
        default="log:",
        description="ZeroMQ topic prefix to subscribe to",
    )
    zmq_reconnect_interval: int = Field(
        default=5,
        description="Seconds between ZeroMQ reconnection attempts",
    )

    # ── Storage ───────────────────────────────────────────────────────────────

    db_path: str = Field(
        default=str(DATA_DIR / "logclaw.duckdb"),
        description="Path to DuckDB database file",
    )
    parquet_dir: str = Field(
        default=str(DATA_DIR / "parquet"),
        description="Directory for Parquet archive files",
    )
    retention_days: int = Field(
        default=90,
        description="Days to retain events in DuckDB before archiving to Parquet",
    )
    archive_interval_hours: int = Field(
        default=24,
        description="Hours between archiving old events to Parquet",
    )

    # ── Ring Buffer ───────────────────────────────────────────────────────────

    ring_buffer_size: int = Field(
        default=50000,
        description="Maximum number of events held in the in-memory ring buffer",
    )

    # ── Correlation Engine ────────────────────────────────────────────────────

    correlation_window_seconds: int = Field(
        default=600,
        description="Sliding window size in seconds for event correlation (default: 10 minutes)",
    )
    brute_force_threshold: int = Field(
        default=10,
        description="Failed login count within window to trigger brute force alert",
    )
    lateral_movement_threshold: int = Field(
        default=3,
        description="Number of distinct hosts an actor authenticates to within window to trigger lateral movement alert",
    )
    after_hours_start: int = Field(
        default=18,
        description="Hour (0-23) after which activity is considered after-hours",
    )
    after_hours_end: int = Field(
        default=7,
        description="Hour (0-23) before which activity is considered after-hours",
    )

    # ── Entity Engine ─────────────────────────────────────────────────────────

    entity_stale_days: int = Field(
        default=90,
        description="Days of inactivity before an entity is considered stale",
    )
    entity_risk_decay_hours: int = Field(
        default=24,
        description="Hours before an entity risk score begins decaying toward baseline",
    )

    # ── Sigma Rules ───────────────────────────────────────────────────────────

    rules_dir: str = Field(
        default=str(RULES_DIR),
        description="Root directory containing Sigma rule YAML files",
    )
    sigma_reload_interval: int = Field(
        default=300,
        description="Seconds between automatic Sigma rule reloads",
    )

    # ── AI Layer ──────────────────────────────────────────────────────────────

    ai_provider: Optional[str] = Field(
        default=None,
        description="AI provider: anthropic | openai | gemini | groq | ollama | None",
    )
    ai_api_key: Optional[str] = Field(
        default=None,
        description="API key for the chosen AI provider",
    )
    ai_model: Optional[str] = Field(
        default=None,
        description="Model override — uses provider default if not set",
    )
    ai_enabled: bool = Field(
        default=False,
        description="Master switch for AI features — False means no AI calls at all",
    )
    ai_max_tokens: int = Field(
        default=800,
        description="Maximum tokens per AI response",
    )
    ai_timeout: int = Field(
        default=30,
        description="Seconds before an AI API call times out",
    )
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for Ollama local AI server",
    )
    ollama_model: str = Field(
        default="llama3",
        description="Ollama model name to use for local AI",
    )

    # ── WebSocket ─────────────────────────────────────────────────────────────

    ws_max_connections: int = Field(
        default=50,
        description="Maximum concurrent WebSocket connections",
    )
    ws_heartbeat_interval: int = Field(
        default=30,
        description="Seconds between WebSocket heartbeat pings",
    )

    # ── Security ──────────────────────────────────────────────────────────────

    secret_key: str = Field(
        default="change-this-in-production-logclaw-secret-key-2026",
        description="Secret key for JWT signing — MUST be changed in production",
    )
    token_expire_hours: int = Field(
        default=24,
        description="Hours before a JWT token expires",
    )
    allow_anonymous: bool = Field(
        default=True,
        description="Allow unauthenticated API access — True for local-only deployments",
    )

    # ── Validators ────────────────────────────────────────────────────────────

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v = v.upper()
        if v not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return v

    @field_validator("ai_provider")
    @classmethod
    def validate_ai_provider(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        valid = {"anthropic", "openai", "gemini", "groq", "ollama"}
        v = v.lower()
        if v not in valid:
            raise ValueError(f"ai_provider must be one of {valid}")
        return v

    @field_validator("after_hours_start", "after_hours_end")
    @classmethod
    def validate_hour(cls, v: int) -> int:
        if not 0 <= v <= 23:
            raise ValueError("Hour must be between 0 and 23")
        return v

    # ── Derived Properties ────────────────────────────────────────────────────

    @property
    def parquet_path(self) -> Path:
        p = Path(self.parquet_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def is_ai_configured(self) -> bool:
        """True if AI is enabled and an API key or Ollama is configured."""
        if not self.ai_enabled:
            return False
        if self.ai_provider == "ollama":
            return True  # Ollama needs no API key
        return bool(self.ai_api_key)

    @property
    def effective_model(self) -> Optional[str]:
        """Returns the model to use — explicit override or provider default."""
        if self.ai_model:
            return self.ai_model
        defaults = {
            "anthropic": "claude-haiku-4-5-20251001",
            "openai":    "gpt-4o",
            "gemini":    "gemini-2.0-flash",
            "groq":      "llama-3.1-8b-instant",
            "ollama":    self.ollama_model,
        }
        return defaults.get(self.ai_provider or "", None)


# ── .env.example Generator ────────────────────────────────────────────────────
# Run this file directly to regenerate the .env.example file.

def generate_env_example():
    """Write a .env.example file to the project root."""
    lines = [
        "# LogClaw Brain — Environment Configuration",
        "# Copy this file to .env and fill in your values",
        "# Built by Rayyan Umair — Technology evolves quickly. Responsibility does not.",
        "",
        "# ── Application ──────────────────────────────────────",
        "LOG_LEVEL=INFO",
        "DEBUG=false",
        "",
        "# ── Server ───────────────────────────────────────────",
        "HOST=0.0.0.0",
        "PORT=8000",
        "",
        "# ── ZeroMQ ───────────────────────────────────────────",
        "# Must match the --zmq flag passed to logclaw-harvester",
        "ZMQ_ADDRESS=tcp://127.0.0.1:5555",
        "",
        "# ── Storage ──────────────────────────────────────────",
        "DB_PATH=./data/logclaw.duckdb",
        "PARQUET_DIR=./data/parquet",
        "RETENTION_DAYS=90",
        "",
        "# ── Correlation ──────────────────────────────────────",
        "CORRELATION_WINDOW_SECONDS=600",
        "BRUTE_FORCE_THRESHOLD=10",
        "LATERAL_MOVEMENT_THRESHOLD=3",
        "AFTER_HOURS_START=18",
        "AFTER_HOURS_END=7",
        "",
        "# ── AI Layer ─────────────────────────────────────────",
        "# Set AI_ENABLED=true and configure a provider to enable AI features",
        "AI_ENABLED=false",
        "# AI_PROVIDER=groq",
        "# AI_API_KEY=your-api-key-here",
        "# AI_MODEL=llama-3.1-8b-instant",
        "",
        "# For local AI via Ollama (no API key needed):",
        "# AI_PROVIDER=ollama",
        "# AI_ENABLED=true",
        "# OLLAMA_BASE_URL=http://localhost:11434",
        "# OLLAMA_MODEL=llama3",
        "",
        "# ── Security ─────────────────────────────────────────",
        "# CHANGE THIS in production — use a long random string",
        "SECRET_KEY=change-this-in-production-logclaw-secret-key-2026",
        "ALLOW_ANONYMOUS=true",
        "",
    ]
    env_example = PROJECT_DIR / ".env.example"
    env_example.write_text("\n".join(lines))
    print(f"Written: {env_example}")


if __name__ == "__main__":
    generate_env_example()
    settings = Settings()
    print(f"\nLoaded settings:")
    print(f"  ZMQ address : {settings.zmq_address}")
    print(f"  DB path     : {settings.db_path}")
    print(f"  AI enabled  : {settings.ai_enabled}")
    print(f"  AI provider : {settings.ai_provider}")
    print(f"  Log level   : {settings.log_level}")