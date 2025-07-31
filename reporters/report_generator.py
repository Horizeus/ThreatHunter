"""
Report Generator for ThreatHunter
Generates detailed analysis reports
"""

import json
import csv
from tabulate import tabulate

class ReportGenerator:
    def __init__(self):
        pass
    
    def generate_text_report(self, report_data, output_file):
        """Generate a human-readable text report"""
        with open(output_file, 'w') as f:
            f.write(self._format_text_report(report_data))
        
    def generate_json_report(self, report_data, output_file):
        """Generate a JSON-formatted report"""
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=4)
        
    def generate_csv_report(self, report_data, output_file):
        """Generate a CSV-formatted report"""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'User', 'Severity', 'Description', 'Computer', 'Event Type'])
            for alert in report_data['alerts']:
                writer.writerow([alert.get('timestamp'), alert.get('user'), alert.get('severity'), alert.get('description'), alert.get('computer'), alert.get('type')])
    
    def _format_text_report(self, report_data):
        """Format the report as a readable text"""
        report_lines = []
        
        report_lines.append(f"Log Analysis Report for {report_data.get('log_file', 'Unknown')}")
        report_lines.append("="*70)
        report_lines.append(f"Log Type: {report_data.get('log_type', 'Unknown')}")
        report_lines.append(f"Analysis Time: {report_data.get('analysis_time', 'Unknown')}")
        report_lines.append(f"Total Events: {report_data.get('total_events', 'Unknown')}")
        report_lines.append(f"Alerts Found: {len(report_data['alerts'])}")
        report_lines.append("="*70)
        
        if report_data['alerts']:
            report_lines.append("Alerts Overview:")
            report_lines.append("-"*70)
            report_lines.append(self._format_alert_summary(report_data['alerts']))
        else:
            report_lines.append("No suspicious activity detected.")
        
        report_lines.append("="*70)
        report_lines.append("Full Event Details:")
        report_lines.append("-"*70)
        for event in report_data['events']:
            report_lines.append(json.dumps(event, indent=4))
        
        return "\n".join(report_lines)
    
    def _format_alert_summary(self, alerts):
        """Format a summary of the alerts"""
        table_headers = ['Timestamp', 'User', 'Severity', 'Description', 'Source']
        table_rows = [
            [alert.get('timestamp'), alert.get('user'), alert.get('severity'), alert.get('description'), alert.get('computer')]
            for alert in alerts
        ]
        
        return tabulate(table_rows, headers=table_headers, tablefmt='grid')

