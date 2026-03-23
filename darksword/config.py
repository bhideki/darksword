"""Configuration management for DarkSword."""

from pathlib import Path
from dataclasses import dataclass
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PAYLOADS_DIR = PROJECT_ROOT / "payloads"
TEMPLATES_DIR = PROJECT_ROOT / "templates"


@dataclass
class ServeConfig:
    """Configuration for the exploit delivery server."""

    host: str = "0.0.0.0"
    port: int = 8080
    redirect_url: Optional[str] = None
    custom_host_in_loader: Optional[str] = None


def get_payloads_dir() -> Path:
    """Get the payloads directory, creating it if needed."""
    PAYLOADS_DIR.mkdir(parents=True, exist_ok=True)
    return PAYLOADS_DIR


def get_templates_dir() -> Path:
    """Get the templates directory, creating it if needed."""
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    return TEMPLATES_DIR
