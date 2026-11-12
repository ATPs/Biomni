"""
Biomni Configuration Management

Simple configuration class for centralizing common settings.
Maintains full backward compatibility with existing code.
"""

import os
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
import inspect


@dataclass
class BiomniConfig:
    """Central configuration for Biomni agent.

    All settings are optional and have sensible defaults.
    API keys are still read from environment variables to maintain
    compatibility with existing .env file structure.

    Usage:
        # Create config with defaults
        config = BiomniConfig()

        # Override specific settings
        config = BiomniConfig(llm="gpt-4", timeout_seconds=1200)

        # Modify after creation
        config.path = "./custom_data"
    """

    # Data and execution settings
    path: str = "./data"
    timeout_seconds: int = 600

    # LLM settings (API keys still from environment)
    llm: str = "claude-sonnet-4-5"
    temperature: float = 0.7

    # Tool settings
    use_tool_retriever: bool = True

    # Data licensing settings
    commercial_mode: bool = False  # If True, excludes non-commercial datasets

    # Custom model settings (for custom LLM serving)
    base_url: str | None = None
    api_key: str | None = field(default=None, repr=False)
    protocol: str | None = None
    rscript_path: str = "Rscript"
    r_library_paths: tuple[str, ...] = ()

    # LLM source (auto-detected if None)
    source: str | None = None

    # Third-party integrations
    protocols_io_access_token: str | None = field(default=None, repr=False)

    def __post_init__(self):
        """Load any environment variable overrides if they exist."""
        # Check for environment variable overrides (optional)
        # Support both old and new names for backwards compatibility
        if os.getenv("BIOMNI_PATH") or os.getenv("BIOMNI_DATA_PATH"):
            self.path = os.getenv("BIOMNI_PATH") or os.getenv("BIOMNI_DATA_PATH")
        if os.getenv("BIOMNI_TIMEOUT_SECONDS"):
            self.timeout_seconds = int(os.getenv("BIOMNI_TIMEOUT_SECONDS"))
        if os.getenv("BIOMNI_LLM") or os.getenv("BIOMNI_LLM_MODEL"):
            self.llm = os.getenv("BIOMNI_LLM") or os.getenv("BIOMNI_LLM_MODEL")
        if os.getenv("BIOMNI_USE_TOOL_RETRIEVER"):
            self.use_tool_retriever = os.getenv("BIOMNI_USE_TOOL_RETRIEVER").lower() == "true"
        if os.getenv("BIOMNI_COMMERCIAL_MODE"):
            self.commercial_mode = os.getenv("BIOMNI_COMMERCIAL_MODE").lower() == "true"
        if os.getenv("BIOMNI_TEMPERATURE"):
            self.temperature = float(os.getenv("BIOMNI_TEMPERATURE"))
        if os.getenv("BIOMNI_CUSTOM_BASE_URL"):
            self.base_url = os.getenv("BIOMNI_CUSTOM_BASE_URL")
        if os.getenv("BIOMNI_CUSTOM_API_KEY"):
            self.api_key = os.getenv("BIOMNI_CUSTOM_API_KEY")
        if os.getenv("BIOMNI_SOURCE"):
            self.source = os.getenv("BIOMNI_SOURCE")
        if os.getenv("BIOMNI_API_PROTOCOL"):
            self.protocol = os.getenv("BIOMNI_API_PROTOCOL")
        if self.protocol not in {None, "chat_completions", "responses"}:
            raise ValueError("Unsupported API protocol")

        # Protocols.io access token (prefer specific env vars)
        env_token = os.getenv("PROTOCOLS_IO_ACCESS_TOKEN") or os.getenv("BIOMNI_PROTOCOLS_IO_ACCESS_TOKEN")
        if env_token:
            self.protocols_io_access_token = env_token

    @property
    def llm_model(self):
        """Compatibility alias for callers using the older attribute name."""
        return self.llm

    @llm_model.setter
    def llm_model(self, value):
        self.llm = value

    def to_dict(self, *, include_secrets=False) -> dict:
        """Convert config to dictionary for easy access."""
        return {
            "path": self.path,
            "timeout_seconds": self.timeout_seconds,
            "llm": self.llm,
            "temperature": self.temperature,
            "use_tool_retriever": self.use_tool_retriever,
            "commercial_mode": self.commercial_mode,
            "base_url": self.base_url,
            "api_key": self.api_key if include_secrets else ("[REDACTED]" if self.api_key else None),
            "source": self.source,
            "protocol": self.protocol,
        }


# Global default config instance (optional, for convenience)
default_config = BiomniConfig()
_task_config = ContextVar("biomni_task_config", default=None)


def effective_config():
    return _task_config.get() or default_config


@contextmanager
def config_context(config):
    token = _task_config.set(config)
    try:
        yield config
    finally:
        _task_config.reset(token)


def task_configured(function):
    """Keep database calls in the invoking agent's context, including streams."""
    if inspect.isgeneratorfunction(function):
        @wraps(function)
        def stream(self, *args, **kwargs):
            with config_context(self.config):
                yield from function(self, *args, **kwargs)
        return stream
    @wraps(function)
    def call(self, *args, **kwargs):
        with config_context(self.config):
            return function(self, *args, **kwargs)
    return call
