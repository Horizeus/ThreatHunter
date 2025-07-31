"""
Simple GUI for ThreatHunter using tkinter
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
from pathlib import Path
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.windows_parser import WindowsLogParser
from parsers.linux_parser import LinuxLogParser
from detectors.behavior_detector import BehaviorDetector
from reporters.report_generator import ReportGenerator

class ThreatHunterGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ThreatHunter - Log Analysis Tool")
        self.root.geometry("800x600")
        
        # Initialize components
        self.behavior_detector = BehaviorDetector()
        self.report_generator = ReportGenerator()
        
        self.setup_gui()
        
    def setup_gui(self):
        """Setup the GUI components"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # File selection
        ttk.Label(main_frame, text="Log File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.file_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.file_var, width=50).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=5)
        
        # Log type selection
        ttk.Label(main_frame, text="Log Type:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.log_type_var = tk.StringVar(value="windows")
        log_type_frame = ttk.Frame(main_frame)
        log_type_frame.grid(row=1, column=1, sticky=tk.W, pady=5)
        ttk.Radiobutton(log_type_frame, text="Windows", variable=self.log_type_var, value="windows").pack(side=tk.LEFT)
        ttk.Radiobutton(log_type_frame, text="Linux", variable=self.log_type_var, value="linux").pack(side=tk.LEFT, padx=10)
        
        # Analyze button
        self.analyze_btn = ttk.Button(main_frame, text="Analyze Logs", command=self.analyze_logs)
        self.analyze_btn.grid(row=2, column=0, columnspan=3, pady=10)
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Analysis Results", padding="5")
        results_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, width=80, height=25)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=2)
    
    def browse_file(self):
        """Open file dialog to select log file"""
        filetypes = [
            ("All Log Files", "*.evtx *.log *.txt"),
            ("Windows Event Logs", "*.evtx"),
            ("Text Files", "*.log *.txt"),
            ("All Files", "*.*")
        ]
        
        filename = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=filetypes
        )
        
        if filename:
            self.file_var.set(filename)
    
    def analyze_logs(self):
        """Analyze the selected log file"""
        log_file = self.file_var.get()
        if not log_file:
            messagebox.showerror("Error", "Please select a log file first.")
            return
        
        if not Path(log_file).exists():
            messagebox.showerror("Error", "Selected file does not exist.")
            return
        
        # Run analysis in a separate thread to prevent GUI freezing
        self.analyze_btn.config(state='disabled')
        self.progress.start()
        self.status_var.set("Analyzing logs...")
        
        thread = threading.Thread(target=self._analyze_worker, args=(log_file,))
        thread.daemon = True
        thread.start()
    
    def _analyze_worker(self, log_file):
        """Worker function for log analysis (runs in separate thread)"""
        try:
            log_type = self.log_type_var.get()
            
            # Parse logs
            if log_type == 'windows':
                parser = WindowsLogParser()
                events = parser.parse_evtx(log_file)
            else:
                parser = LinuxLogParser()
                events = parser.parse_syslog(log_file)
            
            # Detect suspicious behavior
            alerts = self.behavior_detector.analyze_events(events)
            
            # Format results
            results = self._format_results(events, alerts, log_file, log_type)
            
            # Update GUI in main thread
            self.root.after(0, self._update_results, results)
            
        except Exception as e:
            error_msg = f"Analysis failed: {str(e)}"
            self.root.after(0, self._show_error, error_msg)
    
    def _format_results(self, events, alerts, log_file, log_type):
        """Format analysis results for display"""
        results = []
        results.append(f"📁 Log File: {log_file}")
        results.append(f"🔍 Log Type: {log_type.title()}")
        results.append(f"📊 Total Events: {len(events)}")
        results.append(f"🚨 Alerts Found: {len(alerts)}")
        results.append("=" * 60)
        
        if alerts:
            # Group alerts by severity
            high_alerts = [a for a in alerts if a.get('severity') == 'HIGH']
            medium_alerts = [a for a in alerts if a.get('severity') == 'MEDIUM']
            low_alerts = [a for a in alerts if a.get('severity') == 'LOW']
            
            if high_alerts:
                results.append(f"\\n🔴 HIGH PRIORITY ALERTS ({len(high_alerts)}):")
                results.append("-" * 40)
                for alert in high_alerts:
                    results.append(f"• {alert.get('description', 'Unknown alert')}")
                    if alert.get('user'):
                        results.append(f"  User: {alert.get('user')}")
                    if alert.get('computer'):
                        results.append(f"  Computer: {alert.get('computer')}")
                    if alert.get('timestamp'):
                        results.append(f"  Time: {alert.get('timestamp')}")
                    results.append("")
            
            if medium_alerts:
                results.append(f"\\n🟡 MEDIUM PRIORITY ALERTS ({len(medium_alerts)}):")
                results.append("-" * 40)
                for alert in medium_alerts[:5]:  # Show top 5
                    results.append(f"• {alert.get('description', 'Unknown alert')}")
                    if alert.get('user'):
                        results.append(f"  User: {alert.get('user')}")
                    results.append("")
                
                if len(medium_alerts) > 5:
                    results.append(f"... and {len(medium_alerts) - 5} more medium priority alerts")
            
            if low_alerts:
                results.append(f"\\n🔵 LOW PRIORITY ALERTS: {len(low_alerts)}")
        else:
            results.append("\\n✅ No suspicious activity detected!")
        
        results.append("\\n" + "=" * 60)
        results.append("📝 Sample Events:")
        results.append("-" * 40)
        
        for i, event in enumerate(events[:5]):  # Show first 5 events
            results.append(f"\\nEvent {i+1}:")
            results.append(f"  Description: {event.get('description', 'Unknown')}")
            results.append(f"  Timestamp: {event.get('timestamp', 'Unknown')}")
            if event.get('user'):
                results.append(f"  User: {event.get('user')}")
            if event.get('computer') or event.get('hostname'):
                results.append(f"  Computer: {event.get('computer', event.get('hostname'))}")
        
        if len(events) > 5:
            results.append(f"\\n... and {len(events) - 5} more events")
        
        return "\\n".join(results)
    
    def _update_results(self, results):
        """Update the results display (called from main thread)"""
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(1.0, results)
        
        self.progress.stop()
        self.analyze_btn.config(state='normal')
        self.status_var.set("Analysis complete")
    
    def _show_error(self, error_msg):
        """Show error message (called from main thread)"""
        self.progress.stop()
        self.analyze_btn.config(state='normal')
        self.status_var.set("Analysis failed")
        messagebox.showerror("Analysis Error", error_msg)
    
    def run(self):
        """Start the GUI"""
        self.root.mainloop()

if __name__ == "__main__":
    app = ThreatHunterGUI()
    app.run()
