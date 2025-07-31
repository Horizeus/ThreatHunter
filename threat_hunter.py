#!/usr/bin/env python3
"""
ThreatHunter - Log Analysis and Suspicious Behavior Detection Toolkit
Author: ThreatHunter Team
Description: Parses system logs and detects suspicious behavior patterns
"""

import argparse
import sys
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
    def __init__(self):
        self.config = Config()
        self.behavior_detector = BehaviorDetector()
        self.report_generator = ReportGenerator()
        
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
            print(f"{Fore.YELLOW}[*] Analyzing log file: {log_file}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Log type: {log_type}{Style.RESET_ALL}")
            
            # Parse logs based on type
            if log_type.lower() == 'windows':
                parser = WindowsLogParser()
                events = parser.parse_evtx(log_file)
            elif log_type.lower() == 'linux':
                parser = LinuxLogParser()
                events = parser.parse_syslog(log_file)
            else:
                raise ValueError(f"Unsupported log type: {log_type}")
            
            print(f"{Fore.GREEN}[+] Parsed {len(events)} log events{Style.RESET_ALL}")
            
            # Detect suspicious behavior
            print(f"{Fore.YELLOW}[*] Analyzing for suspicious patterns...{Style.RESET_ALL}")
            alerts = self.behavior_detector.analyze_events(events)
            
            print(f"{Fore.RED if alerts else Fore.GREEN}[!] Found {len(alerts)} potential threats{Style.RESET_ALL}")
            
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
            print(f"{Fore.RED}[ERROR] Analysis failed: {str(e)}{Style.RESET_ALL}")
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
  
  # Run GUI mode
  python threat_hunter.py --gui
        """
    )
    
    parser.add_argument('-f', '--file', type=str, help='Log file to analyze')
    parser.add_argument('-t', '--type', choices=['windows', 'linux'], help='Log type')
    parser.add_argument('-o', '--output', choices=['text', 'json', 'csv'], default='text', help='Output format')
    parser.add_argument('--output-file', type=str, help='Output file path')
    parser.add_argument('--gui', action='store_true', help='Launch GUI interface')
    parser.add_argument('--config', type=str, help='Configuration file path')
    
    args = parser.parse_args()
    
    threat_hunter = ThreatHunter()
    threat_hunter.print_banner()
    
    if args.gui:
        from gui.main_window import ThreatHunterGUI
        app = ThreatHunterGUI()
        app.run()
    elif args.file and args.type:
        log_file = Path(args.file)
        if not log_file.exists():
            print(f"{Fore.RED}[ERROR] Log file not found: {log_file}{Style.RESET_ALL}")
            sys.exit(1)
        
        threat_hunter.analyze_logs(log_file, args.type, args.output, args.output_file)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
