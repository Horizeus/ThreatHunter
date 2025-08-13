#!/usr/bin/env python3
"""
ThreatHunter Demo Script
Demonstrates the capabilities of the threat hunting toolkit
"""

import sys
from colorama import init, Fore, Style
from parsers.windows_parser import WindowsLogParser
from parsers.linux_parser import LinuxLogParser
from detectors.behavior_detector import BehaviorDetector
from reporters.report_generator import ReportGenerator
from datetime import datetime

# Initialize colorama
init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.CYAN}+==================================================+
|          [*] THREAT HUNTER DEMO v1.0             |
|       Log Analysis & Threat Detection Demo       |
+==================================================+{Style.RESET_ALL}

{Fore.GREEN}[+] Running demonstration with sample data...{Style.RESET_ALL}
    """
    print(banner)

def demo_windows_analysis():
    """Demonstrate Windows log analysis"""
    print(f"{Fore.YELLOW}{'='*60}")
    print(f"           WINDOWS EVENT LOG ANALYSIS")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    # Initialize components
    parser = WindowsLogParser()
    detector = BehaviorDetector()
    
    # Use built-in sample data (since we don't have real EVTX files)
    print(f"{Fore.CYAN}[*] Parsing Windows events (using built-in samples)...{Style.RESET_ALL}")
    events = parser._generate_sample_events()
    
    print(f"{Fore.GREEN}[+] Parsed {len(events)} Windows events{Style.RESET_ALL}")
    
    # Show sample events
    print(f"\n{Fore.CYAN}[*] Sample Windows Events:{Style.RESET_ALL}")
    for i, event in enumerate(events[:5]):
        print(f"  {i+1}. {event.get('description')} - {event.get('user', 'Unknown user')}")
    
    # Detect threats
    print(f"\n{Fore.YELLOW}[*] Analyzing for suspicious patterns...{Style.RESET_ALL}")
    alerts = detector.analyze_events(events)
    
    print(f"{Fore.RED if alerts else Fore.GREEN}[!] Found {len(alerts)} potential threats{Style.RESET_ALL}")
    
    # Display alerts
    if alerts:
        high_alerts = [a for a in alerts if a.get('severity') == 'HIGH']
        medium_alerts = [a for a in alerts if a.get('severity') == 'MEDIUM']
        
        if high_alerts:
            print(f"\n{Fore.RED}[!] HIGH PRIORITY ALERTS:{Style.RESET_ALL}")
            for alert in high_alerts:
                print(f"   - {alert['description']}")
                if alert.get('user'):
                    print(f"     User: {alert.get('user')}")
                if alert.get('source_ip'):
                    print(f"     Source IP: {alert.get('source_ip')}")
        
        if medium_alerts:
            print(f"\n{Fore.YELLOW}[*] MEDIUM PRIORITY ALERTS:{Style.RESET_ALL}")
            for alert in medium_alerts[:3]:
                print(f"   - {alert['description']}")
    
    return events, alerts

def demo_linux_analysis():
    """Demonstrate Linux log analysis"""
    print(f"\n{Fore.YELLOW}{'='*60}")
    print(f"            LINUX SYSLOG ANALYSIS")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    # Initialize components
    parser = LinuxLogParser()
    detector = BehaviorDetector()
    
    # Use built-in sample data
    print(f"{Fore.CYAN}[*] Parsing Linux syslog (using built-in samples)...{Style.RESET_ALL}")
    events = parser._generate_sample_events()
    
    print(f"{Fore.GREEN}[+] Parsed {len(events)} Linux events{Style.RESET_ALL}")
    
    # Show sample events
    print(f"\n{Fore.CYAN}[*] Sample Linux Events:{Style.RESET_ALL}")
    for i, event in enumerate(events[:5]):
        print(f"  {i+1}. {event.get('description')} - {event.get('hostname', 'Unknown host')}")
    
    # Detect threats
    print(f"\n{Fore.YELLOW}[*] Analyzing for suspicious patterns...{Style.RESET_ALL}")
    alerts = detector.analyze_events(events)
    
    print(f"{Fore.RED if alerts else Fore.GREEN}[!] Found {len(alerts)} potential threats{Style.RESET_ALL}")
    
    # Display alerts
    if alerts:
        high_alerts = [a for a in alerts if a.get('severity') == 'HIGH']
        medium_alerts = [a for a in alerts if a.get('severity') == 'MEDIUM']
        
        if high_alerts:
            print(f"\n{Fore.RED}[!] HIGH PRIORITY ALERTS:{Style.RESET_ALL}")
            for alert in high_alerts:
                print(f"   - {alert['description']}")
                if alert.get('user'):
                    print(f"     User: {alert.get('user')}")
                if alert.get('source_ip'):
                    print(f"     Source IP: {alert.get('source_ip')}")
        
        if medium_alerts:
            print(f"\n{Fore.YELLOW}[*] MEDIUM PRIORITY ALERTS:{Style.RESET_ALL}")
            for alert in medium_alerts[:3]:
                print(f"   - {alert['description']}")
    
    return events, alerts

def demo_report_generation(all_events, all_alerts):
    """Demonstrate report generation"""
    print(f"\n{Fore.YELLOW}{'='*60}")
    print(f"            REPORT GENERATION")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    # Create report data
    report_data = {
        'log_file': 'Demo Analysis',
        'log_type': 'Mixed (Windows + Linux)',
        'analysis_time': datetime.now().isoformat(),
        'total_events': len(all_events),
        'alerts': all_alerts,
        'events': all_events[:10]  # Limit events in report
    }
    
    # Generate reports
    reporter = ReportGenerator()
    
    print(f"{Fore.CYAN}[*] Generating reports...{Style.RESET_ALL}")
    
    # Text report
    reporter.generate_text_report(report_data, 'demo_threathunter_output.txt')
    print(f"{Fore.GREEN}[+] Text report saved: demo_threathunter_output.txt{Style.RESET_ALL}")
    
    # JSON report
    reporter.generate_json_report(report_data, 'demo_threathunter_output.json')
    print(f"{Fore.GREEN}[+] JSON report saved: demo_threathunter_output.json{Style.RESET_ALL}")
    
    # CSV report
    reporter.generate_csv_report(report_data, 'demo_threathunter_output.csv')
    print(f"{Fore.GREEN}[+] CSV report saved: demo_threathunter_output.csv{Style.RESET_ALL}")

def demo_features():
    """Demonstrate additional features"""
    print(f"\n{Fore.YELLOW}{'='*60}")
    print(f"            TOOLKIT FEATURES")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    features = [
        "[+] Multi-platform log parsing (Windows EVTX + Linux syslog)",
        "[+] Brute force attack detection (5+ failed logins in 5 minutes)",
        "[+] PowerShell abuse detection (Base64 encoded commands)",
        "[+] Suspicious process detection (mimikatz, psexec, netcat, etc.)",
        "[+] Off-hours activity monitoring",
        "[+] Privilege escalation detection",
        "[+] Lateral movement detection",
        "[+] Account anomaly detection",
        "[+] Multiple output formats (Text, JSON, CSV)",
        "[+] CLI interface available",
        "[+] VirusTotal integration (with API key)",
        "[+] Elasticsearch integration (optional)",
        "[+] Configurable detection rules",
        "[+] Colored terminal output",
        "[+] Progress tracking and status updates"
    ]
    
    for feature in features:
        print(f"  {feature}")

def main():
    """Main demo function"""
    print_banner()
    
    # Demo Windows analysis
    win_events, win_alerts = demo_windows_analysis()
    
    # Demo Linux analysis  
    linux_events, linux_alerts = demo_linux_analysis()
    
    # Combine results
    all_events = win_events + linux_events
    all_alerts = win_alerts + linux_alerts
    
    # Demo report generation
    demo_report_generation(all_events, all_alerts)
    
    # Show features
    demo_features()
    
    # Final summary
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"              DEMO SUMMARY")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[*] Total Events Analyzed: {len(all_events)}{Style.RESET_ALL}")
    print(f"{Fore.RED if all_alerts else Fore.GREEN}[!] Total Threats Detected: {len(all_alerts)}{Style.RESET_ALL}")
    
    # Group alerts by severity
    if all_alerts:
        high_count = len([a for a in all_alerts if a.get('severity') == 'HIGH'])
        medium_count = len([a for a in all_alerts if a.get('severity') == 'MEDIUM'])
        low_count = len([a for a in all_alerts if a.get('severity') == 'LOW'])
        
        print(f"   - HIGH priority: {high_count}")
        print(f"   - MEDIUM priority: {medium_count}")
        print(f"   - LOW priority: {low_count}")
    
    print(f"\n{Fore.YELLOW}[*] To use ThreatHunter:{Style.RESET_ALL}")
    print(f"   Command line: python threat_hunter.py -f logfile.evtx -t windows")
    print(f"   Interactive:  python threat_hunter.py --interactive")
    print(f"   Help:         python threat_hunter.py --help")
    
    print(f"\n{Fore.GREEN}[+] Demo completed! Check the generated report files.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
