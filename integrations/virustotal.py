"""
VirusTotal API Integration
Provides hash checking and threat intelligence
"""

import requests
import hashlib
import time
from pathlib import Path

class VirusTotalClient:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.headers = {"User-Agent": "ThreatHunter v1.0"}
    
    def check_file_hash(self, file_hash):
        """Check a file hash against VirusTotal database"""
        if not self.api_key:
            return {"error": "No API key configured"}
        
        url = f"{self.base_url}/file/report"
        params = {
            "apikey": self.api_key,
            "resource": file_hash
        }
        
        try:
            response = requests.get(url, params=params, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}: {response.text}"}
                
        except requests.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}
    
    def check_url(self, url):
        """Check a URL against VirusTotal database"""
        if not self.api_key:
            return {"error": "No API key configured"}
        
        vt_url = f"{self.base_url}/url/report"
        params = {
            "apikey": self.api_key,
            "resource": url
        }
        
        try:
            response = requests.get(vt_url, params=params, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}: {response.text}"}
                
        except requests.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}
    
    def calculate_file_hash(self, file_path, algorithm='sha256'):
        """Calculate hash of a file"""
        hash_func = getattr(hashlib, algorithm)()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            return None
    
    def batch_check_hashes(self, hash_list):
        """Check multiple hashes with rate limiting"""
        results = {}
        
        for file_hash in hash_list:
            results[file_hash] = self.check_file_hash(file_hash)
            # Rate limiting: VT free API allows 4 requests per minute
            time.sleep(15)
        
        return results
    
    def enrich_event_with_vt(self, event):
        """Enrich an event with VirusTotal data if applicable"""
        enriched_event = event.copy()
        
        # Check if event has process information
        process_name = event.get('process_name')
        if process_name and Path(process_name).exists():
            file_hash = self.calculate_file_hash(process_name)
            if file_hash:
                vt_result = self.check_file_hash(file_hash)
                enriched_event['virustotal'] = {
                    'hash': file_hash,
                    'result': vt_result
                }
        
        # Check command line for URLs
        command_line = event.get('command_line', '')
        urls = self._extract_urls(command_line)
        if urls:
            enriched_event['virustotal_urls'] = {}
            for url in urls:
                vt_result = self.check_url(url)
                enriched_event['virustotal_urls'][url] = vt_result
                time.sleep(15)  # Rate limiting
        
        return enriched_event
    
    def _extract_urls(self, text):
        """Extract URLs from text"""
        import re
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
    
    def is_malicious(self, vt_result):
        """Determine if VT result indicates malicious content"""
        if isinstance(vt_result, dict) and 'positives' in vt_result and 'total' in vt_result:
            positives = vt_result.get('positives', 0)
            total = vt_result.get('total', 0)
            
            if total > 0:
                detection_ratio = positives / total
                return detection_ratio > 0.1  # Consider malicious if >10% detect
        
        return False
