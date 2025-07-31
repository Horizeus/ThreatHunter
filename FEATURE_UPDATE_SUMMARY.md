# ThreatHunter Feature Update: YAML Config & Smart GUI Fallback

## Overview
This update enhances ThreatHunter with improved configuration management and robust GUI fallback mechanisms.

## 🧾 YAML Configuration Support

### New Features:
- **Dual Format Support**: Configuration files now support both YAML (.yaml/.yml) and JSON (.json) formats
- **Automatic Detection**: The system automatically detects and loads the appropriate format
- **YAML Validation**: Built-in schema validation ensures configuration integrity
- **Default Config Generation**: Create template configurations with proper structure

### Updated Files:
- `utils/config.py` - Enhanced to load/save both YAML and JSON
- `utils/yaml_validator.py` - New validation module with schema checking
- `threat_hunter.py` - Updated to prefer YAML config when available

### Configuration Priority:
1. YAML config (config.yaml) - **Preferred**
2. JSON config (config.json) - **Fallback**
3. Default hardcoded config - **Last resort**

### Usage Examples:
```bash
# Validate existing YAML config
python -m utils.yaml_validator config.yaml

# Create a new default YAML configuration
python -m utils.yaml_validator --create-default --output my_config.yaml

# Use custom config file
python threat_hunter.py --config my_config.yaml -f logfile.evtx -t windows
```

### YAML Configuration Schema:
The validator enforces proper structure including:
- **Logging**: Level, format, file rotation settings
- **Detection Rules**: Enabled/disabled, thresholds, severity levels
- **Application Settings**: Output formats, GUI preferences
- **GUI Configuration**: Theme, refresh rates, fallback settings
- **Integrations**: VirusTotal, Elasticsearch, SIEM connections

## 🧠 Smart GUI Fallback

### Enhanced Features:
- **Retry Mechanism**: Configurable retry attempts (1-10 times)
- **Progressive Delays**: Customizable retry delays (1-60 seconds)
- **User Feedback**: Progress indicators showing retry attempts
- **Graceful Degradation**: Falls back to CLI mode if GUI fails completely

### Updated Files:
- `gui/main_window.py` - Enhanced with retry logic and better error handling
- `threat_hunter.py` - Improved GUI launch with fallback to CLI

### Configuration Options:
```yaml
gui:
  fallback:
    enabled: true           # Enable/disable retry mechanism
    retry_attempts: 3       # Number of retry attempts (1-10)
    retry_delay: 5          # Delay between retries in seconds (1-60)
```

### Fallback Behavior:
1. **First Attempt**: Normal GUI launch
2. **On Failure**: Show retry dialog with countdown
3. **Subsequent Attempts**: Progressive retry with user feedback
4. **Final Fallback**: Graceful exit to CLI mode with help message

### User Experience Improvements:
- Real-time status updates during analysis
- Progress bars with attempt indicators
- Clear error messages with next steps
- Automatic retry without user intervention
- Manual retry option available

## 🔧 Technical Improvements

### Dependencies Added:
- `pyyaml` - YAML parsing and generation
- `jsonschema` - Configuration validation

### Error Handling:
- Robust YAML parsing with fallback to JSON
- Schema validation with detailed error messages
- GUI exception handling with graceful degradation
- Configuration file corruption detection

### Performance Enhancements:
- Lazy loading of GUI components
- Async analysis with threaded operations
- Memory-efficient configuration caching
- Optimized retry timing

## 📋 Configuration Migration

### For Existing Users:
1. **Keep existing config.json** - Still fully supported
2. **Optional**: Convert to YAML using the validator tool
3. **New installs**: Use YAML by default

### Migration Command:
```bash
# Create YAML version of current config
python -m utils.yaml_validator --create-default --output config.yaml
```

## 🧪 Testing & Validation

### Validation Tests:
```bash
# Test YAML config validation
python -m utils.yaml_validator config.yaml

# Test GUI fallback
python threat_hunter.py --gui

# Test CLI fallback
python threat_hunter.py -f sample.log -t windows
```

### Configuration Examples:
- `config.yaml` - Full production configuration
- `config_new.yaml` - Generated default configuration
- Both formats validated and working

## 📈 Benefits

### For Users:
- **Easier Configuration**: Human-readable YAML format
- **Better Reliability**: Smart retry mechanisms
- **Improved UX**: Clear feedback and progress indicators
- **Flexible Deployment**: Works in GUI and CLI environments

### For Administrators:
- **Centralized Config**: Single file for all settings
- **Validation Tools**: Built-in schema checking
- **Deployment Ready**: Template generation capabilities
- **Error Recovery**: Automatic fallback mechanisms

## 🚀 Next Steps

### Recommended Actions:
1. **Update Dependencies**: Install pyyaml and jsonschema
2. **Validate Config**: Run validator on existing configurations
3. **Test GUI**: Verify fallback mechanisms work as expected
4. **Generate Templates**: Create organization-specific config templates

### Future Enhancements:
- GUI configuration editor
- Live config reloading
- Advanced rule customization
- Integration with external config management systems

---

## File Changes Summary

### Modified Files:
- ✅ `utils/config.py` - Added YAML support
- ✅ `gui/main_window.py` - Enhanced fallback mechanism
- ✅ `threat_hunter.py` - Improved config handling and GUI fallback

### New Files:
- ✅ `utils/yaml_validator.py` - Configuration validation tool
- ✅ `config_new.yaml` - Generated default YAML configuration
- ✅ `FEATURE_UPDATE_SUMMARY.md` - This documentation

### Dependencies:
- ✅ PyYAML 6.0.2
- ✅ jsonschema 4.25.0

The ThreatHunter system now provides a more robust, user-friendly configuration experience with intelligent GUI fallback capabilities.
