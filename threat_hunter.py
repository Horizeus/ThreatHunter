#!/usr/bin/env python3
"""
ThreatHunter - Log Analysis and Suspicious Behavior Detection Toolkit
Author: ThreatHunter Team
Description: Parses system logs and detects suspicious behavior patterns
"""

import argparse
import sys
import logging
from datetime import datetime
from pathlib import Path

from colorama import init, Fore, Style

# Initialize colorama for Windows support
init(autoreset=True)

from parsers.windows_parser import WindowsLogParser
from parsers.linux_parser import LinuxLogParser
from detectors.behavior_detector import BehaviorDetector
from reporters.report_generator import ReportGenerator
from utils.config import Config

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
def display_summary(alerts):
    """Display analysis summary"""
    print(f"\n{Fore.CYAN}{'='*50}")
    print(f"           THREAT ANALYSIS SUMMARY")
    print(f"{'='*50}{Style.RESET_ALL}")

    if not alerts:
        print(f"{Fore.GREEN}✓ No suspicious activity detected{Style.RESET_ALL}")
        return

    # Group alerts by severity
    high_alerts = [a for a in alerts if a.get('severity') == 'HIGH']
    medium_alerts = [a for a in alerts if a.get('severity') == 'MEDIUM']
    low_alerts = [a for a in alerts if a.get('severity') == 'LOW']

    print(f"{Fore.RED}🚨 HIGH PRIORITY ALERTS: {len(high_alerts)}{Style.RESET_ALL}")
    for alert in high_alerts[:3]:  # Show top 3
        print(f"   • {alert['description']}")

    print(f"{Fore.YELLOW}⚠️  MEDIUM PRIORITY ALERTS: {len(medium_alerts)}{Style.RESET_ALL}")
    for alert in medium_alerts[:3]:  # Show top 3
        print(f"   • {alert['description']}")

    print(f"{Fore.BLUE}ℹ️  LOW PRIORITY ALERTS: {len(low_alerts)}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}📊 Full report saved to output file{Style.RESET_ALL}")


class ThreatHunter:
    def __init__(self, config_file=None):
        # Default to YAML config if it exists, fallback to JSON
        if config_file is None:
            config_file = 'config.yaml' if Path('config.yaml').exists() else 'config.json'
        
        self.config = Config(config_file)
        self.behavior_detector = BehaviorDetector()
        self.report_generator = ReportGenerator()
    
    def interactive_mode(self):
        """Interactive CLI mode to replace GUI functionality"""
        print(f"{Fore.CYAN}\n🔍 Welcome to ThreatHunter Interactive Mode{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Choose an option below or type 'help' for more information.{Style.RESET_ALL}")
        
        while True:
            print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}ThreatHunter Interactive Menu:{Style.RESET_ALL}")
            print(f"  1. 🔍 Analyze log file")
            print(f"  2. 📋 Run demo with sample data")
            print(f"  3. 📊 View system information")
            print(f"  4. ⚙️  Configure settings")
            print(f"  5. 📚 Show help")
            print(f"  6. 🚪 Exit")
            
            try:
                choice = input(f"\n{Fore.YELLOW}Enter your choice (1-6): {Style.RESET_ALL}").strip()
                
                if choice == '1':
                    self._interactive_analyze()
                elif choice == '2':
                    self._run_demo()
                elif choice == '3':
                    self._show_system_info()
                elif choice == '4':
                    self._configure_settings()
                elif choice == '5':
                    self._show_help()
                elif choice == '6':
                    print(f"{Fore.GREEN}\n👋 Thank you for using ThreatHunter!{Style.RESET_ALL}")
                    break
                elif choice.lower() == 'help':
                    self._show_help()
                else:
                    print(f"{Fore.RED}❌ Invalid choice. Please select 1-6.{Style.RESET_ALL}")
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}\n👋 Goodbye!{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}❌ Error: {str(e)}{Style.RESET_ALL}")
    
    def _interactive_analyze(self):
        """Interactive log analysis"""
        print(f"\n{Fore.CYAN}📁 Log File Analysis{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please provide the following information:{Style.RESET_ALL}")
        
        # Get log file path
        while True:
            log_file_input = input(f"\n📄 Enter log file path (or 'back' to return): ").strip()
            
            if log_file_input.lower() == 'back':
                return
            
            log_file = Path(log_file_input)
            if log_file.exists():
                break
            else:
                print(f"{Fore.RED}❌ File not found: {log_file}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}💡 Tip: Use absolute path or relative to current directory{Style.RESET_ALL}")
        
        # Get log type
        while True:
            print(f"\n🔍 Select log type:")
            print(f"  1. Windows Event Logs (.evtx)")
            print(f"  2. Linux Syslog (.log, .txt)")
            
            log_type_choice = input(f"Enter choice (1-2): ").strip()
            
            if log_type_choice == '1':
                log_type = 'windows'
                break
            elif log_type_choice == '2':
                log_type = 'linux'
                break
            else:
                print(f"{Fore.RED}❌ Invalid choice. Please select 1 or 2.{Style.RESET_ALL}")
        
        # Get output format
        while True:
            print(f"\n📊 Select output format:")
            print(f"  1. Text (.txt) - Human readable")
            print(f"  2. JSON (.json) - Machine readable")
            print(f"  3. CSV (.csv) - Spreadsheet format")
            
            format_choice = input(f"Enter choice (1-3, default=1): ").strip() or '1'
            
            if format_choice == '1':
                output_format = 'text'
                break
            elif format_choice == '2':
                output_format = 'json'
                break
            elif format_choice == '3':
                output_format = 'csv'
                break
            else:
                print(f"{Fore.RED}❌ Invalid choice. Please select 1, 2, or 3.{Style.RESET_ALL}")
        
        # Optional output file
        output_file = input(f"\n📝 Custom output filename (optional, press Enter to use default): ").strip() or None
        
        # Confirm and analyze
        print(f"\n{Fore.CYAN}📋 Analysis Summary:{Style.RESET_ALL}")
        print(f"  📁 File: {log_file}")
        print(f"  🔍 Type: {log_type.title()}")
        print(f"  📊 Format: {output_format.upper()}")
        print(f"  📝 Output: {output_file or 'Default filename'}")
        
        confirm = input(f"\n{Fore.YELLOW}Proceed with analysis? (y/N): {Style.RESET_ALL}").strip().lower()
        
        if confirm in ['y', 'yes']:
            print(f"\n{Fore.GREEN}🚀 Starting analysis...{Style.RESET_ALL}")
            result = self.analyze_logs(log_file, log_type, output_format, output_file)
            
            if result:
                print(f"\n{Fore.GREEN}✅ Analysis completed successfully!{Style.RESET_ALL}")
                input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.RED}❌ Analysis failed. Check the logs for details.{Style.RESET_ALL}")
                input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}📝 Analysis cancelled.{Style.RESET_ALL}")
    
    def _run_demo(self):
        """Run demonstration with sample data"""
        print(f"\n{Fore.CYAN}🎯 Running ThreatHunter Demo{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}This will demonstrate the tool's capabilities using built-in sample data.{Style.RESET_ALL}")
        
        confirm = input(f"\n{Fore.YELLOW}Continue with demo? (Y/n): {Style.RESET_ALL}").strip().lower()
        
        if confirm not in ['n', 'no']:
            try:
                # Import and run demo
                import demo
                demo.main()
                input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
            except ImportError:
                print(f"{Fore.RED}❌ Demo module not found. Please ensure demo.py exists.{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}❌ Demo failed: {str(e)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}📝 Demo cancelled.{Style.RESET_ALL}")
    
    def _show_system_info(self):
        """Display system and tool information"""
        import platform
        try:
            import psutil
            psutil_available = True
        except ImportError:
            psutil_available = False
        
        print(f"\n{Fore.CYAN}💻 System Information{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*40}{Style.RESET_ALL}")
        
        # System info
        print(f"🖥️  Operating System: {platform.system()} {platform.release()}")
        print(f"🏗️  Architecture: {platform.machine()}")
        print(f"🐍 Python Version: {platform.python_version()}")
        
        # Memory info
        if psutil_available:
            try:
                memory = psutil.virtual_memory()
                print(f"💾 Memory: {memory.total // (1024**3):.1f} GB total, {memory.available // (1024**3):.1f} GB available")
            except:
                print(f"💾 Memory: Information unavailable")
        else:
            print(f"💾 Memory: Information unavailable (psutil not installed)")
        
        # Tool info
        print(f"\n{Fore.CYAN}🔧 ThreatHunter Information{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*40}{Style.RESET_ALL}")
        print(f"📦 Version: 1.0 Alpha")
        print(f"📁 Working Directory: {Path.cwd()}")
        
        # Check for config files
        config_files = ['config.yaml', 'config.json']
        for config_file in config_files:
            if Path(config_file).exists():
                print(f"⚙️  Configuration: {config_file} ✅")
            else:
                print(f"⚙️  Configuration: {config_file} ❌")
        
        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
    
    def _configure_settings(self):
        """Configure tool settings"""
        print(f"\n{Fore.CYAN}⚙️  ThreatHunter Configuration{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Current configuration options:{Style.RESET_ALL}")
        
        print(f"\n1. 📊 Output directory")
        print(f"2. 🔍 Detection sensitivity")
        print(f"3. 📝 Logging level")
        print(f"4. 🌐 Integration settings (VirusTotal, etc.)")
        print(f"5. 🔙 Back to main menu")
        
        choice = input(f"\n{Fore.YELLOW}Select option (1-5): {Style.RESET_ALL}").strip()
        
        if choice == '1':
            print(f"\n{Fore.YELLOW}📊 Output Directory Configuration{Style.RESET_ALL}")
            current_dir = Path.cwd()
            print(f"Current: {current_dir}")
            new_dir = input(f"Enter new output directory (or press Enter to keep current): ").strip()
            if new_dir:
                print(f"✅ Output directory would be set to: {new_dir}")
                print(f"{Fore.YELLOW}💡 Note: This is a demonstration. Actual configuration requires config file modification.{Style.RESET_ALL}")
        
        elif choice == '2':
            print(f"\n{Fore.YELLOW}🔍 Detection Sensitivity{Style.RESET_ALL}")
            print(f"1. High (more alerts, potential false positives)")
            print(f"2. Medium (balanced)")
            print(f"3. Low (fewer alerts, conservative)")
            sens_choice = input(f"Select sensitivity (1-3): ").strip()
            if sens_choice in ['1', '2', '3']:
                levels = {'1': 'High', '2': 'Medium', '3': 'Low'}
                print(f"✅ Sensitivity would be set to: {levels[sens_choice]}")
        
        elif choice == '3':
            print(f"\n{Fore.YELLOW}📝 Logging Level{Style.RESET_ALL}")
            print(f"1. DEBUG (verbose)")
            print(f"2. INFO (standard)")
            print(f"3. WARNING (minimal)")
            print(f"4. ERROR (errors only)")
            log_choice = input(f"Select level (1-4): ").strip()
            if log_choice in ['1', '2', '3', '4']:
                levels = {'1': 'DEBUG', '2': 'INFO', '3': 'WARNING', '4': 'ERROR'}
                print(f"✅ Logging level would be set to: {levels[log_choice]}")
        
        elif choice == '4':
            print(f"\n{Fore.YELLOW}🌐 Integration Settings{Style.RESET_ALL}")
            print(f"Configure external service integrations:")
            print(f"• VirusTotal API")
            print(f"• Elasticsearch")
            print(f"• Custom webhooks")
            print(f"\n{Fore.CYAN}💡 Edit config.yaml or config.json to configure integrations.{Style.RESET_ALL}")
        
        elif choice == '5':
            return
        
        else:
            print(f"{Fore.RED}❌ Invalid choice.{Style.RESET_ALL}")
        
        if choice != '5':
            input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
    
    def _show_help(self):
        """Show help information"""
        print(f"\n{Fore.CYAN}📚 ThreatHunter Help{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}🎯 What is ThreatHunter?{Style.RESET_ALL}")
        print(f"ThreatHunter is a log analysis toolkit that detects suspicious")
        print(f"behavior patterns in system logs. It supports Windows Event Logs")
        print(f"(.evtx) and Linux syslog files.")
        
        print(f"\n{Fore.GREEN}🔍 Supported Log Types:{Style.RESET_ALL}")
        print(f"• Windows Event Logs (.evtx) - Security, System, Application logs")
        print(f"• Linux Syslog (.log, .txt) - /var/log/syslog, /var/log/auth.log")
        
        print(f"\n{Fore.GREEN}🚨 Detection Capabilities:{Style.RESET_ALL}")
        print(f"• Brute force attacks (multiple failed logins)")
        print(f"• PowerShell abuse (base64 encoded commands)")
        print(f"• Suspicious processes (mimikatz, psexec, etc.)")
        print(f"• Off-hours activity")
        print(f"• Privilege escalation attempts")
        print(f"• Lateral movement indicators")
        print(f"• Account anomalies")
        
        print(f"\n{Fore.GREEN}📊 Output Formats:{Style.RESET_ALL}")
        print(f"• Text (.txt) - Human-readable reports")
        print(f"• JSON (.json) - Machine-readable data")
        print(f"• CSV (.csv) - Spreadsheet compatible")
        
        print(f"\n{Fore.GREEN}💻 Command Line Usage:{Style.RESET_ALL}")
        print(f"python threat_hunter.py -f logfile.evtx -t windows")
        print(f"python threat_hunter.py -f /var/log/syslog -t linux -o json")
        print(f"python threat_hunter.py --interactive  # This mode")
        print(f"python demo.py  # Run demonstration")
        
        print(f"\n{Fore.GREEN}🔧 Configuration:{Style.RESET_ALL}")
        print(f"Edit config.yaml or config.json to customize:")
        print(f"• Detection rules and thresholds")
        print(f"• Output preferences")
        print(f"• Integration settings (VirusTotal, etc.)")
        
        print(f"\n{Fore.GREEN}📞 Support:{Style.RESET_ALL}")
        print(f"For issues or questions, check the documentation")
        print(f"or contact the ThreatHunter team.")
        
        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
        
    @staticmethod
    def print_banner():
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════╗
║        THREAT HUNTER v1.0 Alpha           ║
║      Log Analysis & Threat Detection      ║
╚═══════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.GREEN}[+] Initializing threat hunting toolkit...{Style.RESET_ALL}
        """
        print(banner)
    
    def analyze_logs(self, log_file, log_type, output_format='text', output_file=None):
        """Main analysis function"""
        try:
            logger.info(f"Analyzing log file: {log_file}")
            logger.info(f"Log type: {log_type}")
            
            # Parse logs based on type
            if log_type.lower() == 'windows':
                parser = WindowsLogParser()
                events = parser.parse_evtx(log_file)
            elif log_type.lower() == 'linux':
                parser = LinuxLogParser()
                events = parser.parse_syslog(log_file)
            else:
                raise ValueError(f"Unsupported log type: {log_type}")

            logger.info(f"Parsed {len(events)} log events")
            
            # Detect suspicious behavior
            logger.info("Analyzing for suspicious patterns...")
            alerts = self.behavior_detector.analyze_events(events)
            
            logger.warning(f"Found {len(alerts)} potential threats" if alerts else "No potential threats found.")

            # Generate report
            report_data = {
                'log_file': str(log_file),
                'log_type': log_type,
                'analysis_time': datetime.now().isoformat(),
                'total_events': len(events),
                'alerts': alerts,
                'events': events[:100]  # Limit events in report
            }
            
            # Output report
            if output_format.lower() == 'json':
                output_file = output_file or 'threathunter_output.json'
                self.report_generator.generate_json_report(report_data, output_file)
            elif output_format.lower() == 'csv':
                output_file = output_file or 'threathunter_output.csv'
                self.report_generator.generate_csv_report(report_data, output_file)
            else:
                output_file = output_file or 'threathunter_output.txt'
                self.report_generator.generate_text_report(report_data, output_file)
            
            # Display summary
            display_summary(alerts)
            
            return report_data
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            return None


def main():
    parser = argparse.ArgumentParser(
        description="ThreatHunter - Log Analysis and Suspicious Behavior Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze Windows Event Log
  python threat_hunter.py -f Security.evtx -t windows
  
  # Analyze Linux syslog with JSON output
  python threat_hunter.py -f /var/log/syslog -t linux -o json
  
  # Interactive mode
  python threat_hunter.py --interactive
        """
    )
    
    parser.add_argument('-f', '--file', type=str, help='Log file to analyze')
    parser.add_argument('-t', '--type', choices=['windows', 'linux'], help='Log type')
    parser.add_argument('-o', '--output', choices=['text', 'json', 'csv'], default='text', help='Output format')
    parser.add_argument('--output-file', type=str, help='Output file path')
    parser.add_argument('--interactive', '-i', action='store_true', help='Launch interactive CLI mode')
    parser.add_argument('--config', type=str, help='Configuration file path')
    
    args = parser.parse_args()
    
    threat_hunter = ThreatHunter()
    threat_hunter.print_banner()
    
    if args.interactive:
        threat_hunter.interactive_mode()
    elif args.file and args.type:
        log_file = Path(args.file)
        if not log_file.exists():
            print(f"{Fore.RED}[ERROR] Log file not found: {log_file}{Style.RESET_ALL}")
            sys.exit(1)
        
        threat_hunter.analyze_logs(log_file, args.type, args.output, args.output_file)
    else:
        print(f"\n{Fore.CYAN}🔍 ThreatHunter CLI Usage:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Interactive mode:{Style.RESET_ALL} python threat_hunter.py --interactive")
        print(f"  {Fore.YELLOW}Direct analysis:{Style.RESET_ALL} python threat_hunter.py -f logfile.evtx -t windows")
        print(f"  {Fore.YELLOW}Run demo:{Style.RESET_ALL} python demo.py")
        print(f"  {Fore.YELLOW}Full help:{Style.RESET_ALL} python threat_hunter.py --help")
        print(f"\n{Fore.GREEN}💡 For the best experience, try: python threat_hunter.py --interactive{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
