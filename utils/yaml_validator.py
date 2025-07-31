"""
YAML Configuration Validator for ThreatHunter
Validates configuration files and detection rules
"""

import yaml
import jsonschema
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class YAMLConfigValidator:
    def __init__(self):
        self.schema = self._get_config_schema()
    
    def _get_config_schema(self):
        """Define the expected YAML configuration schema"""
        return {
            "type": "object",
            "properties": {
                "logging": {
                    "type": "object",
                    "properties": {
                        "level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]},
                        "format": {"type": "string"},
                        "file": {"type": "string"},
                        "max_file_size": {"type": "integer"},
                        "backup_count": {"type": "integer"}
                    },
                    "required": ["level", "format", "file"]
                },
                "detection_rules": {
                    "type": "object",
                    "patternProperties": {
                        "^[a-zA-Z_][a-zA-Z0-9_]*$": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean"},
                                "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                                "description": {"type": "string"},
                                "threshold": {"type": "integer", "minimum": 1},
                                "time_window": {"type": "integer", "minimum": 1}
                            },
                            "required": ["enabled", "severity", "description"]
                        }
                    }
                },
                "application": {
                    "type": "object",
                    "properties": {
                        "version": {"type": "string"},
                        "default_output_format": {"type": "string", "enum": ["text", "json", "csv"]},
                        "max_events_in_report": {"type": "integer", "minimum": 1},
                        "enable_gui_fallback": {"type": "boolean"},
                        "plugin_auto_discovery": {"type": "boolean"}
                    }
                },
                "gui": {
                    "type": "object",
                    "properties": {
                        "theme": {"type": "string", "enum": ["light", "dark"]},
                        "auto_refresh": {"type": "integer", "minimum": 1},
                        "max_displayed_alerts": {"type": "integer", "minimum": 1},
                        "enable_notifications": {"type": "boolean"},
                        "fallback": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean"},
                                "retry_attempts": {"type": "integer", "minimum": 1, "maximum": 10},
                                "retry_delay": {"type": "integer", "minimum": 1, "maximum": 60}
                            },
                            "required": ["enabled", "retry_attempts", "retry_delay"]
                        }
                    }
                },
                "integrations": {
                    "type": "object",
                    "properties": {
                        "virustotal": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean"},
                                "api_key": {"type": "string"},
                                "rate_limit": {"type": "integer", "minimum": 1},
                                "timeout": {"type": "integer", "minimum": 1}
                            },
                            "required": ["enabled"]
                        },
                        "elasticsearch": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean"},
                                "host": {"type": "string"},
                                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                                "index": {"type": "string"}
                            },
                            "required": ["enabled"]
                        }
                    }
                }
            },
            "required": ["logging", "detection_rules", "application"]
        }
    
    def validate_yaml_file(self, yaml_file_path):
        """Validate a YAML configuration file"""
        try:
            yaml_path = Path(yaml_file_path)
            if not yaml_path.exists():
                return False, f"YAML file not found: {yaml_file_path}"
            
            with open(yaml_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            # Validate against schema
            jsonschema.validate(config_data, self.schema)
            
            # Additional custom validations
            validation_errors = self._custom_validations(config_data)
            if validation_errors:
                return False, f"Custom validation errors: {', '.join(validation_errors)}"
            
            logger.info(f"YAML configuration file '{yaml_file_path}' is valid")
            return True, "Configuration is valid"
            
        except yaml.YAMLError as e:
            return False, f"YAML parsing error: {str(e)}"
        except jsonschema.ValidationError as e:
            return False, f"Schema validation error: {str(e)}"
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    def _custom_validations(self, config_data):
        """Perform custom validation logic"""
        errors = []
        
        # Validate detection rules have reasonable thresholds
        if 'detection_rules' in config_data:
            for rule_name, rule_config in config_data['detection_rules'].items():
                if 'threshold' in rule_config and rule_config['threshold'] > 1000:
                    errors.append(f"Rule '{rule_name}' has unusually high threshold: {rule_config['threshold']}")
                
                if 'time_window' in rule_config and rule_config['time_window'] > 86400:  # 24 hours
                    errors.append(f"Rule '{rule_name}' has unusually long time window: {rule_config['time_window']} seconds")
        
        # Validate GUI fallback settings
        if 'gui' in config_data and 'fallback' in config_data['gui']:
            fallback = config_data['gui']['fallback']
            if fallback.get('retry_attempts', 0) > 5:
                errors.append("GUI fallback retry_attempts should not exceed 5 for user experience")
        
        # Validate integration settings
        if 'integrations' in config_data:
            integrations = config_data['integrations']
            if 'virustotal' in integrations and integrations['virustotal'].get('enabled'):
                if not integrations['virustotal'].get('api_key'):
                    errors.append("VirusTotal integration is enabled but no API key provided")
        
        return errors
    
    def get_default_yaml_config(self):
        """Generate a default YAML configuration"""
        default_config = {
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file': 'threathunter.log',
                'max_file_size': 10485760,
                'backup_count': 5
            },
            'detection_rules': {
                'brute_force': {
                    'enabled': True,
                    'threshold': 5,
                    'time_window': 300,
                    'severity': 'HIGH',
                    'description': 'Multiple failed login attempts detected'
                },
                'privilege_escalation': {
                    'enabled': True,
                    'severity': 'HIGH',
                    'description': 'Privilege escalation attempt detected',
                    'suspicious_commands': ['sudo su', 'runas', 'net user', 'whoami /priv']
                },
                'suspicious_processes': {
                    'enabled': True,
                    'severity': 'MEDIUM',
                    'description': 'Suspicious process execution detected',
                    'blacklisted_processes': [
                        'powershell.exe -enc',
                        'cmd.exe /c echo',
                        'wscript.exe',
                        'cscript.exe'
                    ]
                }
            },
            'application': {
                'version': '1.0.0',
                'default_output_format': 'text',
                'max_events_in_report': 1000,
                'enable_gui_fallback': True,
                'plugin_auto_discovery': True
            },
            'gui': {
                'theme': 'dark',
                'auto_refresh': 30,
                'max_displayed_alerts': 50,
                'enable_notifications': True,
                'fallback': {
                    'enabled': True,
                    'retry_attempts': 3,
                    'retry_delay': 5
                }
            },
            'integrations': {
                'virustotal': {
                    'enabled': False,
                    'api_key': '',
                    'rate_limit': 4,
                    'timeout': 30
                },
                'elasticsearch': {
                    'enabled': False,
                    'host': 'localhost',
                    'port': 9200,
                    'index': 'threathunter'
                }
            }
        }
        return default_config
    
    def create_default_yaml_file(self, output_path='config_default.yaml'):
        """Create a default YAML configuration file"""
        try:
            default_config = self.get_default_yaml_config()
            
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump(default_config, f, default_flow_style=False, indent=2, sort_keys=False)
            
            logger.info(f"Default YAML configuration created: {output_path}")
            return True, f"Default configuration created: {output_path}"
            
        except Exception as e:
            return False, f"Failed to create default config: {str(e)}"

def main():
    """CLI tool for validating YAML configs"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ThreatHunter YAML Configuration Validator")
    parser.add_argument('config_file', nargs='?', help='YAML configuration file to validate')
    parser.add_argument('--create-default', action='store_true', help='Create a default configuration file')
    parser.add_argument('--output', '-o', default='config_default.yaml', help='Output file for default config')
    
    args = parser.parse_args()
    
    validator = YAMLConfigValidator()
    
    if args.create_default:
        success, message = validator.create_default_yaml_file(args.output)
        print(f"{'✓' if success else '✗'} {message}")
        return 0 if success else 1
    
    if args.config_file:
        is_valid, message = validator.validate_yaml_file(args.config_file)
        print(f"{'✓' if is_valid else '✗'} {message}")
        return 0 if is_valid else 1
    
    parser.print_help()
    return 0

if __name__ == "__main__":
    exit(main())
