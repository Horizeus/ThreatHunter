# 🔍 ThreatHunter - Log Analysis & Threat Detection Toolkit

A comprehensive Python toolkit for analyzing system logs (Windows/Linux) and detecting suspicious behavior patterns.

## ✨ Features

- **Multi-platform Log Parsing**
  - Windows Event Logs (EVTX format)
  - Linux syslog files
  - Structured data extraction with regex patterns

- **Advanced Threat Detection**
  - Brute force attack detection (5+ failed logins in 5 minutes)
  - PowerShell abuse detection (Base64 encoded commands)
  - Suspicious process execution (mimikatz, psexec, netcat, etc.)
  - Off-hours activity monitoring
  - Privilege escalation attempts
  - Lateral movement detection
  - Account anomaly detection
  - Network-based threats

- **Multiple Output Formats**
  - Human-readable text reports
  - JSON format for automation
  - CSV format for spreadsheet analysis
  - Colored terminal output

- **Bonus Features**
  - 🖥️ GUI interface using tkinter
  - 🔍 VirusTotal API integration
  - 📊 Elasticsearch integration (optional)
  - ⚙️ Configurable detection rules
  - 🚀 Progress tracking and status updates

## 📋 Requirements

- Python 3.7+
- Windows or Linux operating system
- See `requirements.txt` for full dependency list

## 🚀 Installation

1. **Clone or download the project**
   ```bash
   # If using git
   git clone https://github.com/Horizeus/ThreatHunter.git
   
   # Or download and extract the files
   ```

2. **Install dependencies**
   ```bash
   cd threat_hunter
   pip install -r requirements.txt
   ```

3. **Verify installation**
   ```bash
   python threat_hunter.py --help
   ```

## 💻 Usage

### Command Line Interface

```bash
# Analyze Windows Event Log
python threat_hunter.py -f Security.evtx -t windows

# Analyze Linux syslog with JSON output
python threat_hunter.py -f /var/log/syslog -t linux -o json

# Specify custom output file
python threat_hunter.py -f logfile.evtx -t windows --output-file my_report.txt

# Generate CSV report
python threat_hunter.py -f auth.log -t linux -o csv
```

### GUI Mode

```bash
# Launch the graphical interface
python threat_hunter.py --gui
```

The GUI provides an intuitive interface for:
- Selecting log files
- Choosing log types
- Running analysis
- Viewing results in real-time

### Demo Mode

```bash
# Run a comprehensive demonstration
python demo.py
```

## 📊 Detection Rules

### Brute Force Attacks
- **Trigger**: 5+ failed login attempts within 5 minutes
- **Severity**: HIGH
- **Covers**: SSH, RDP, Windows authentication

### PowerShell Abuse
- **Trigger**: Base64 encoded commands, suspicious keywords
- **Severity**: HIGH/MEDIUM
- **Keywords**: `-EncodedCommand`, `Invoke-Expression`, `DownloadString`

### Suspicious Processes
- **Trigger**: Known hacking tools
- **Severity**: HIGH
- **Processes**: mimikatz, psexec, netcat, wce, procdump

### Off-Hours Activity
- **Trigger**: User management outside business hours (8 AM - 6 PM)
- **Severity**: MEDIUM
- **Activities**: User creation, password changes, group modifications

## 🔧 Configuration

Create a `config.json` file to customize detection rules:

```json
{
  "detection_rules": {
    "brute_force_threshold": 5,
    "brute_force_time_window": 300,
    "business_hours": {
      "start": 8,
      "end": 18,
      "weekdays_only": true
    }
  },
  "integrations": {
    "virustotal": {
      "enabled": false,
      "api_key": "your_vt_api_key_here"
    }
  }
}
```

## 📁 Project Structure

```
threat_hunter/
├── threat_hunter.py          # Main application entry point
├── demo.py                   # Demonstration script
├── requirements.txt          # Python dependencies
├── config.json              # Configuration file (optional)
├── parsers/                 # Log parsing modules
│   ├── windows_parser.py    # Windows Event Log parser
│   └── linux_parser.py     # Linux syslog parser
├── detectors/               # Threat detection engines
│   └── behavior_detector.py # Main detection logic
├── reporters/               # Report generation
│   └── report_generator.py # Text, JSON, CSV reports
├── integrations/            # External API integrations
│   └── virustotal.py       # VirusTotal API client
├── utils/                   # Utility modules
│   └── config.py           # Configuration management
├── gui/                     # Graphical interface
│   └── main_window.py      # tkinter GUI
└── sample_logs/            # Sample log files for testing
```

## 🎯 Example Output

```
╔═══════════════════════════════════════════╗
║        🔍 THREAT HUNTER v1.0 Alpha        ║
║      Log Analysis & Threat Detection      ║
╚═══════════════════════════════════════════╝

[+] Parsed 27 log events
[!] Found 6 potential threats

🚨 HIGH PRIORITY ALERTS: 3
   • Brute force attack detected: 5 failed login attempts for user "administrator" from 10.0.0.50 within 5 minutes
   • PowerShell Base64 encoded command detected
   • Suspicious user account created: backup_admin

⚠️  MEDIUM PRIORITY ALERTS: 3
   • Suspicious PowerShell keyword detected: bypass
   • Suspicious activity outside business hours: User Account Created
   • Suspicious command pattern detected

📊 Full report saved to threathunter_output.txt
```

## 🔍 VirusTotal Integration

To enable VirusTotal integration:

1. Get a free API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Add it to your `config.json`:
   ```json
   {
     "integrations": {
       "virustotal": {
         "enabled": true,
         "api_key": "your_api_key_here"
       }
     }
   }
   ```

## 🐛 Troubleshooting

### Common Issues

1. **"python-evtx not found" error**
   ```bash
   pip install python-evtx
   ```

2. **Permission errors on log files**
   - Run as administrator/root when analyzing system logs
   - Copy log files to accessible location

3. **GUI not starting**
   - Ensure tkinter is installed (usually comes with Python)
   - On Linux: `sudo apt-get install python3-tk`

4. **No events parsed**
   - Check log file format and path
   - Verify log type selection (windows/linux)
   - Try the demo mode to verify installation

## 🧪 Testing

Run the built-in demonstration:
```bash
python demo.py
```

This will:
- Analyze sample Windows and Linux events
- Demonstrate threat detection capabilities
- Generate sample reports
- Show all available features

## 📄 License

This project is provided as-is for educational and security research purposes.

## 🤝 Contributing

Feel free to submit issues, feature requests, or pull requests to improve the toolkit.

## 🔒 Security Note

This tool is designed for legitimate security analysis and threat hunting. Always ensure you have proper authorization before analyzing system logs.

---

**Happy Threat Hunting! 🔍🛡️**
