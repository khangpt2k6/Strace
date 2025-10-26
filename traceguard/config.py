"""Configuration management for TraceGuard"""

import os
import json
from pathlib import Path
from typing import Optional
from .models import Config


class ConfigManager:
    """Manages TraceGuard configuration"""
    
    DEFAULT_CONFIG_LOCATIONS = [
        ".traceguard.json",
        ".traceguard/config.json",
        "~/.traceguard/config.json",
        "/etc/traceguard/config.json",
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config()
        self.config = self._load_config()
    
    def _find_config(self) -> Optional[str]:
        """Find configuration file in standard locations"""
        for location in self.DEFAULT_CONFIG_LOCATIONS:
            path = Path(location).expanduser()
            if path.exists():
                return str(path)
        return None
    
    def _load_config(self) -> Config:
        """Load configuration from file or use defaults"""
        if self.config_path and Path(self.config_path).exists():
            with open(self.config_path, 'r') as f:
                data = json.load(f)
            return Config(**data)
        return Config()
    
    def save(self, path: str) -> None:
        """Save current configuration to file"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.config.dict(), f, indent=2)
    
    def get(self) -> Config:
        """Get current configuration"""
        return self.config
    
    def update(self, **kwargs) -> None:
        """Update configuration values"""
        data = self.config.dict()
        data.update(kwargs)
        self.config = Config(**data)


def get_default_config() -> Config:
    """Get default configuration"""
    return Config()