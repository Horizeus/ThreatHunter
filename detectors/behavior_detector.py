"""
Behavior Detection Engine
Analyzes events and detects suspicious behavior patterns
"""

import re
import base64
from datetime import datetime, timedelta
from collections import defaultdict
from dateutil import parser

class BehaviorDetector:
    def __init__(self):
        self.suspicious_patterns = {
            'powershell_base64': {
                'pattern': r'-EncodedCommand|FromBase64String|Convert\.FromBase64String',
                'severity': 'HIGH',
                'description': 'PowerShell Base64 encoded command execution detected'
            },
            'suspicious_processes': {
                'processes': ['nc.exe', 'netcat.exe', 'psexec.exe', 'wce.exe', 'mimikatz.exe', 'procdump.exe'],
                'severity': 'HIGH',
                'description': 'Suspicious process execution detected'
            },
            'privilege_escalation': {
                'commands': ['runas', 'whoami /priv', 'net localgroup administrators', 'getsystem'],
                'severity': 'HIGH',
                'description': 'Potential privilege escalation attempt'
            },
            'lateral_movement': {
                'commands': ['psexec', 'wmic', 'sc.exe', 'net use', 'at.exe', 'schtasks'],
                'severity': 'MEDIUM',
                'description': 'Potential lateral movement activity'
            },
            'suspicious_network': {
                'domains': ['pastebin.com', 'bit.ly', 'tinyurl.com', 'dropbox.com'],
                'ips': ['10.0.0.1', '192.168.1.1'],  # Example suspicious IPs
                'severity': 'MEDIUM',
                'description': 'Suspicious network activity detected'
            }
        }
        
        # Business hours configuration (24-hour format)
        self.business_hours = {
            'start': 8,  # 8 AM
            'end': 18,   # 6 PM
            'weekdays_only': True
        }
    
    def analyze_events(self, events):
        """Main analysis function"""
        alerts = []
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: self._parse_timestamp(x.get('timestamp', '')))
        
        # Run detection rules
        alerts.extend(self._detect_brute_force_attacks(sorted_events))
        alerts.extend(self._detect_powershell_abuse(sorted_events))
        alerts.extend(self._detect_suspicious_processes(sorted_events))
        alerts.extend(self._detect_off_hours_activity(sorted_events))
        alerts.extend(self._detect_privilege_escalation(sorted_events))
        alerts.extend(self._detect_lateral_movement(sorted_events))
        alerts.extend(self._detect_suspicious_commands(sorted_events))
        alerts.extend(self._detect_account_anomalies(sorted_events))
        alerts.extend(self._detect_network_anomalies(sorted_events))
        
        return alerts
    
    def _parse_timestamp(self, timestamp_str):
        """Parse timestamp string to datetime object"""
        try:
            if isinstance(timestamp_str, str):
                return parser.parse(timestamp_str)
            return timestamp_str or datetime.min
        except:
            return datetime.min
    
    def _detect_brute_force_attacks(self, events):
        """Detect brute force login attempts"""
        alerts = []
        failed_logins = defaultdict(list)
        
        for event in events:
            # Windows failed logins
            if (event.get('event_id') == 4625 or 
                (event.get('pattern') in ['ssh_login_failed', 'ssh_invalid_user'] and 
                 event.get('success') is False)):
                
                key = f"{event.get('user', 'unknown')}@{event.get('source_ip', 'unknown')}"
                failed_logins[key].append(event)
        
        # Check for multiple failures in short time window
        for key, failures in failed_logins.items():
            if len(failures) >= 5:
                # Check if failures occurred within 5 minutes
                time_window = timedelta(minutes=5)
                failures.sort(key=lambda x: self._parse_timestamp(x.get('timestamp', '')))
                
                for i in range(len(failures) - 4):
                    window_failures = failures[i:i+5]
                    start_time = self._parse_timestamp(window_failures[0].get('timestamp', ''))
                    end_time = self._parse_timestamp(window_failures[-1].get('timestamp', ''))
                    
                    if end_time - start_time <= time_window:
                        user, source_ip = key.split('@')
                        alerts.append({
                            'type': 'brute_force_attack',
                            'severity': 'HIGH',
                            'description': f'Brute force attack detected: {len(window_failures)} failed login attempts for user "{user}" from {source_ip} within 5 minutes',
                            'timestamp': start_time.isoformat(),
                            'user': user,
                            'source_ip': source_ip,
                            'failure_count': len(window_failures),
                            'events': window_failures
                        })
                        break
        
        return alerts
    
    def _detect_powershell_abuse(self, events):
        """Detect PowerShell abuse patterns"""
        alerts = []
        
        for event in events:
            command_line = event.get('command_line', '') or event.get('script_block', '')
            
            if command_line:
                # Check for base64 encoded commands
                if re.search(self.suspicious_patterns['powershell_base64']['pattern'], command_line, re.IGNORECASE):
                    # Try to decode base64 content
                    decoded_content = self._decode_base64_commands(command_line)
                    
                    alerts.append({
                        'type': 'powershell_base64',
                        'severity': 'HIGH',
                        'description': 'PowerShell Base64 encoded command detected',
                        'timestamp': event.get('timestamp'),
                        'user': event.get('user', 'Unknown'),
                        'command': command_line,
                        'decoded_content': decoded_content,
                        'computer': event.get('computer', event.get('hostname', 'Unknown')),
                        'event': event
                    })
                
                # Check for other suspicious PowerShell patterns
                suspicious_keywords = [
                    'Invoke-Expression', 'IEX', 'DownloadString', 'WebRequest',
                    'Invoke-Command', 'Start-Process', 'New-Object Net.WebClient',
                    'bypass', 'unrestricted', 'hidden', 'noprofile'
                ]
                
                for keyword in suspicious_keywords:
                    if keyword.lower() in command_line.lower():
                        alerts.append({
                            'type': 'suspicious_powershell',
                            'severity': 'MEDIUM',
                            'description': f'Suspicious PowerShell keyword detected: {keyword}',
                            'timestamp': event.get('timestamp'),
                            'user': event.get('user', 'Unknown'),
                            'command': command_line,
                            'keyword': keyword,
                            'computer': event.get('computer', event.get('hostname', 'Unknown')),
                            'event': event
                        })
                        break
        
        return alerts
    
    def _detect_suspicious_processes(self, events):
        """Detect suspicious process executions"""
        alerts = []
        
        for event in events:
            process_name = event.get('process_name', '').lower()
            command_line = event.get('command_line', '').lower()
            
            if process_name:
                for sus_process in self.suspicious_patterns['suspicious_processes']['processes']:
                    if sus_process.lower() in process_name:
                        alerts.append({
                            'type': 'suspicious_process',
                            'severity': 'HIGH',
                            'description': f'Suspicious process execution: {sus_process}',
                            'timestamp': event.get('timestamp'),
                            'user': event.get('user', 'Unknown'),
                            'process': process_name,
                            'command': event.get('command_line', ''),
                            'computer': event.get('computer', event.get('hostname', 'Unknown')),
                            'event': event
                        })
            
            # Check for living-off-the-land binaries (LOLBins)
            lolbins = ['certutil', 'bitsadmin', 'regsvr32', 'rundll32', 'mshta', 'cscript', 'wscript']
            for lolbin in lolbins:
                if lolbin in process_name or lolbin in command_line:
                    alerts.append({
                        'type': 'lolbin_usage',
                        'severity': 'MEDIUM',
                        'description': f'Living-off-the-land binary usage: {lolbin}',
                        'timestamp': event.get('timestamp'),
                        'user': event.get('user', 'Unknown'),
                        'process': process_name,
                        'command': event.get('command_line', ''),
                        'lolbin': lolbin,
                        'computer': event.get('computer', event.get('hostname', 'Unknown')),
                        'event': event
                    })
        
        return alerts
    
    def _detect_off_hours_activity(self, events):
        """Detect activity outside business hours"""
        alerts = []
        
        for event in events:
            timestamp = self._parse_timestamp(event.get('timestamp', ''))
            
            if timestamp == datetime.min:
                continue
            
            # Check if activity is outside business hours
            is_off_hours = False
            
            if self.business_hours['weekdays_only'] and timestamp.weekday() >= 5:  # Weekend
                is_off_hours = True
            elif (timestamp.hour < self.business_hours['start'] or 
                  timestamp.hour >= self.business_hours['end']):
                is_off_hours = True
            
            if is_off_hours:
                # Only alert for certain types of activities
                if (event.get('event_id') in [4720, 4722, 4728] or  # Windows user management
                    event.get('pattern') in ['user_add', 'user_del', 'sudo_command'] or  # Linux user management
                    event.get('event_id') == 4688):  # Process creation
                    
                    alerts.append({
                        'type': 'off_hours_activity',
                        'severity': 'MEDIUM',
                        'description': f'Suspicious activity outside business hours: {event.get("description", "Unknown activity")}',
                        'timestamp': event.get('timestamp'),
                        'user': event.get('user', event.get('target_user', 'Unknown')),
                        'activity': event.get('description'),
                        'computer': event.get('computer', event.get('hostname', 'Unknown')),
                        'event': event
                    })
        
        return alerts
    
    def _detect_privilege_escalation(self, events):
        """Detect privilege escalation attempts"""
        alerts = []
        
        for event in events:
            command = event.get('command_line', '') or event.get('command', '')
            
            if command:
                for priv_command in self.suspicious_patterns['privilege_escalation']['commands']:
                    if priv_command.lower() in command.lower():
                        alerts.append({
                            'type': 'privilege_escalation',
                            'severity': 'HIGH',
                            'description': f'Potential privilege escalation: {priv_command}',
                            'timestamp': event.get('timestamp'),
                            'user': event.get('user', 'Unknown'),
                            'command': command,
                            'technique': priv_command,
                            'computer': event.get('computer', event.get('hostname', 'Unknown')),
                            'event': event
                        })
        
        return alerts
    
    def _detect_lateral_movement(self, events):
        """Detect lateral movement attempts"""
        alerts = []
        
        for event in events:
            command = event.get('command_line', '') or event.get('command', '')
            
            if command:
                for lat_command in self.suspicious_patterns['lateral_movement']['commands']:
                    if lat_command.lower() in command.lower():
                        alerts.append({
                            'type': 'lateral_movement',
                            'severity': 'MEDIUM',
                            'description': f'Potential lateral movement: {lat_command}',
                            'timestamp': event.get('timestamp'),
                            'user': event.get('user', 'Unknown'),
                            'command': command,
                            'technique': lat_command,
                            'computer': event.get('computer', event.get('hostname', 'Unknown')),
                            'event': event
                        })
        
        return alerts
    
    def _detect_suspicious_commands(self, events):
        """Detect suspicious command patterns"""
        alerts = []
        
        suspicious_command_patterns = [
            r'curl.*\|\s*bash',
            r'wget.*\|\s*sh',
            r'powershell.*-windowstyle\s+hidden',
            r'cmd\.exe.*\/c.*&',
            r'echo.*>\s*\\\\.*\\pipe',
            r'net\s+user.*\/add',
            r'chmod\s+\+x.*\/tmp\/'
        ]
        
        for event in events:
            command = event.get('command_line', '') or event.get('command', '') or event.get('raw_message', '')
            
            if command:
                for pattern in suspicious_command_patterns:
                    if re.search(pattern, command, re.IGNORECASE):
                        alerts.append({
                            'type': 'suspicious_command',
                            'severity': 'MEDIUM',
                            'description': f'Suspicious command pattern detected',
                            'timestamp': event.get('timestamp'),
                            'user': event.get('user', 'Unknown'),
                            'command': command,
                            'pattern': pattern,
                            'computer': event.get('computer', event.get('hostname', 'Unknown')),
                            'event': event
                        })
        
        return alerts
    
    def _detect_account_anomalies(self, events):
        """Detect account-related anomalies"""
        alerts = []
        
        # Track user creation events
        for event in events:
            if (event.get('event_id') == 4720 or 
                event.get('pattern') == 'user_add'):
                
                user = event.get('target_user', event.get('user', 'Unknown'))
                
                # Check for suspicious usernames
                suspicious_names = ['admin', 'administrator', 'root', 'service', 'backup', 'test', 'guest']
                if any(sus_name in user.lower() for sus_name in suspicious_names):
                    alerts.append({
                        'type': 'suspicious_user_creation',
                        'severity': 'HIGH',
                        'description': f'Suspicious user account created: {user}',
                        'timestamp': event.get('timestamp'),
                        'created_user': user,
                        'created_by': event.get('subject_user', 'Unknown'),
                        'computer': event.get('computer', event.get('hostname', 'Unknown')),
                        'event': event
                    })
        
        return alerts
    
    def _detect_network_anomalies(self, events):
        """Detect network-related anomalies"""
        alerts = []
        
        for event in events:
            # Check for connections to suspicious domains/IPs
            message = event.get('raw_message', '') or event.get('command', '') or event.get('command_line', '')
            
            if message:
                for domain in self.suspicious_patterns['suspicious_network']['domains']:
                    if domain in message.lower():
                        alerts.append({
                            'type': 'suspicious_domain',
                            'severity': 'MEDIUM',
                            'description': f'Connection to suspicious domain: {domain}',
                            'timestamp': event.get('timestamp'),
                            'user': event.get('user', 'Unknown'),
                            'domain': domain,
                            'context': message,
                            'computer': event.get('computer', event.get('hostname', 'Unknown')),
                            'event': event
                        })
        
        return alerts
    
    def _decode_base64_commands(self, command_line):
        """Attempt to decode base64 content from command line"""
        decoded_parts = []
        
        # Find base64 patterns
        base64_patterns = [
            r'-EncodedCommand\s+([A-Za-z0-9+/=]+)',
            r'FromBase64String\(["\']([A-Za-z0-9+/=]+)["\']',
            r'Convert\.FromBase64String\(["\']([A-Za-z0-9+/=]+)["\']'
        ]
        
        for pattern in base64_patterns:
            matches = re.findall(pattern, command_line, re.IGNORECASE)
            for match in matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    decoded_parts.append(decoded)
                except:
                    decoded_parts.append(f'[Failed to decode: {match[:50]}...]')
        
        return decoded_parts
