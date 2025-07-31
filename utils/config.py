"""
Configuration module for ThreatHunter
Manages application settings and configurations
"""

import json
import os
from pathlib import Path

class Config:
    def __init__(self, config_file=None):
        self.config_file = config_file or 'config.json'
        self.config_data = self._load_config()
    
    def _load_config(self):
        """Load configuration from file or create default"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading config: {e}")
                return self._get_default_config()
        else:
            return self._get_default_config()
    
    def _get_default_config(self):
        """Return default configuration"""
        return {
            "detection_rules": {
                "brute_force_threshold": 5,
                "brute_force_time_window": 300,  # seconds
                "business_hours": {
                    "start": 8,
                    "end": 18,
                    "weekdays_only": True
                }
            },
            "output": {
                "default_format": "text",
                "default_file": "threathunter_output.txt"
            },
            "integrations": {
                "virustotal": {
                    "enabled": False,
                    "api_key": ""
                },
                "elasticsearch": {
                    "enabled": False,
                    "host": "localhost",
                    "port": 9200
                }
            }
        }
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config_data, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get(self, key, default=None):
        """Get configuration value"""
        keys = key.split('.')
        value = self.config_data
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def set(self, key, value):
        """Set configuration value"""
        keys = key.split('.')
        config = self.config_data
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
