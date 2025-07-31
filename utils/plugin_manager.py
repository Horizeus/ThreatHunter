"""
Plugin Management System for ThreatHunter
Provides automatic plugin discovery and loading capabilities
"""

import os
import sys
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Any, Type
import logging

logger = logging.getLogger(__name__)

class PluginInterface:
    """Base interface that all plugins must implement"""
    
    @property
    def name(self) -> str:
        """Plugin name"""
        raise NotImplementedError
    
    @property
    def version(self) -> str:
        """Plugin version"""
        raise NotImplementedError
    
    @property
    def description(self) -> str:
        """Plugin description"""
        raise NotImplementedError
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin with configuration"""
        raise NotImplementedError
    
    def cleanup(self) -> None:
        """Cleanup plugin resources"""
        pass

class DetectorPlugin(PluginInterface):
    """Base class for detector plugins"""
    
    def detect(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze events and return alerts"""
        raise NotImplementedError

class ParserPlugin(PluginInterface):
    """Base class for parser plugins"""
    
    @property
    def supported_formats(self) -> List[str]:
        """List of supported log formats"""
        raise NotImplementedError
    
    def parse(self, log_file: str) -> List[Dict[str, Any]]:
        """Parse log file and return events"""
        raise NotImplementedError

class IntegrationPlugin(PluginInterface):
    """Base class for integration plugins"""
    
    def connect(self) -> bool:
        """Establish connection to external service"""
        raise NotImplementedError
    
    def query(self, data: Any) -> Dict[str, Any]:
        """Query external service with data"""
        raise NotImplementedError

class PluginManager:
    """Manages plugin discovery, loading, and lifecycle"""
    
    def __init__(self, plugin_dirs: List[str] = None):
        self.plugin_dirs = plugin_dirs or ['plugins', 'detectors', 'parsers', 'integrations']
        self.loaded_plugins: Dict[str, PluginInterface] = {}
        self.plugin_registry: Dict[str, Dict[str, Any]] = {
            'detectors': {},
            'parsers': {},
            'integrations': {}
        }
        
    def discover_plugins(self) -> Dict[str, List[str]]:
        """Discover available plugins in plugin directories"""
        discovered = {
            'detectors': [],
            'parsers': [],
            'integrations': []
        }
        
        for plugin_dir in self.plugin_dirs:
            if not os.path.exists(plugin_dir):
                logger.warning(f"Plugin directory not found: {plugin_dir}")
                continue
                
            logger.info(f"Scanning plugin directory: {plugin_dir}")
            
            for file_path in Path(plugin_dir).rglob("*.py"):
                if file_path.name.startswith('__'):
                    continue
                    
                try:
                    plugin_info = self._analyze_plugin_file(file_path)
                    if plugin_info:
                        plugin_type = plugin_info['type']
                        if plugin_type in discovered:
                            discovered[plugin_type].append(str(file_path))
                            logger.info(f"Discovered {plugin_type} plugin: {plugin_info['name']}")
                        
                except Exception as e:
                    logger.error(f"Error analyzing plugin file {file_path}: {e}")
                    
        return discovered
    
    def _analyze_plugin_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze a Python file to determine if it contains a valid plugin"""
        try:
            # Create module spec and load module
            spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Look for plugin classes
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if obj.__module__ != module.__name__:
                    continue
                    
                # Check if it's a plugin class
                if issubclass(obj, DetectorPlugin) and obj != DetectorPlugin:
                    return {
                        'name': name,
                        'type': 'detectors',
                        'class': obj,
                        'module': module,
                        'file_path': str(file_path)
                    }
                elif issubclass(obj, ParserPlugin) and obj != ParserPlugin:
                    return {
                        'name': name,
                        'type': 'parsers',
                        'class': obj,
                        'module': module,
                        'file_path': str(file_path)
                    }
                elif issubclass(obj, IntegrationPlugin) and obj != IntegrationPlugin:
                    return {
                        'name': name,
                        'type': 'integrations',
                        'class': obj,
                        'module': module,
                        'file_path': str(file_path)
                    }
                    
        except Exception as e:
            logger.debug(f"Failed to analyze {file_path}: {e}")
            
        return None
    
    def load_plugin(self, plugin_path: str, config: Dict[str, Any] = None) -> bool:
        """Load a specific plugin"""
        try:
            plugin_info = self._analyze_plugin_file(Path(plugin_path))
            if not plugin_info:
                logger.error(f"No valid plugin found in {plugin_path}")
                return False
                
            plugin_class = plugin_info['class']
            plugin_instance = plugin_class()
            
            # Initialize plugin
            if plugin_instance.initialize(config or {}):
                plugin_name = plugin_instance.name
                self.loaded_plugins[plugin_name] = plugin_instance
                
                # Register in appropriate category
                plugin_type = plugin_info['type']
                self.plugin_registry[plugin_type][plugin_name] = plugin_instance
                
                logger.info(f"Successfully loaded plugin: {plugin_name}")
                return True
            else:
                logger.error(f"Failed to initialize plugin: {plugin_instance.name}")
                return False
                
        except Exception as e:
            logger.error(f"Error loading plugin from {plugin_path}: {e}")
            return False
    
    def load_all_plugins(self, config: Dict[str, Any] = None) -> Dict[str, int]:
        """Load all discovered plugins"""
        discovered = self.discover_plugins()
        results = {'loaded': 0, 'failed': 0}
        
        for plugin_type, plugin_files in discovered.items():
            for plugin_file in plugin_files:
                if self.load_plugin(plugin_file, config):
                    results['loaded'] += 1
                else:
                    results['failed'] += 1
                    
        logger.info(f"Plugin loading complete. Loaded: {results['loaded']}, Failed: {results['failed']}")
        return results
    
    def get_plugins_by_type(self, plugin_type: str) -> Dict[str, PluginInterface]:
        """Get all loaded plugins of a specific type"""
        return self.plugin_registry.get(plugin_type, {})
    
    def get_plugin(self, plugin_name: str) -> PluginInterface:
        """Get a specific loaded plugin by name"""
        return self.loaded_plugins.get(plugin_name)
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a specific plugin"""
        try:
            if plugin_name in self.loaded_plugins:
                plugin = self.loaded_plugins[plugin_name]
                plugin.cleanup()
                
                # Remove from registry
                for plugin_type in self.plugin_registry:
                    if plugin_name in self.plugin_registry[plugin_type]:
                        del self.plugin_registry[plugin_type][plugin_name]
                        break
                
                del self.loaded_plugins[plugin_name]
                logger.info(f"Successfully unloaded plugin: {plugin_name}")
                return True
            else:
                logger.warning(f"Plugin not found: {plugin_name}")
                return False
                
        except Exception as e:
            logger.error(f"Error unloading plugin {plugin_name}: {e}")
            return False
    
    def unload_all_plugins(self) -> None:
        """Unload all plugins"""
        for plugin_name in list(self.loaded_plugins.keys()):
            self.unload_plugin(plugin_name)
    
    def get_plugin_info(self) -> Dict[str, Any]:
        """Get information about all loaded plugins"""
        info = {
            'total_loaded': len(self.loaded_plugins),
            'by_type': {},
            'plugins': {}
        }
        
        for plugin_type, plugins in self.plugin_registry.items():
            info['by_type'][plugin_type] = len(plugins)
            
        for name, plugin in self.loaded_plugins.items():
            info['plugins'][name] = {
                'name': plugin.name,
                'version': plugin.version,
                'description': plugin.description,
                'type': type(plugin).__name__
            }
            
        return info
