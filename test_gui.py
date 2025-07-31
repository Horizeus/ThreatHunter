#!/usr/bin/env python3
"""
Test script to verify GUI components work
"""

import sys
try:
    print("Testing GUI imports...")
    from gui.main_window import ThreatHunterGUI
    print("✅ GUI imports successful!")
    
    print("Testing tkinter availability...")
    import tkinter as tk
    root = tk.Tk()
    root.withdraw()  # Hide the window
    print("✅ tkinter is available!")
    root.destroy()
    
    print("Testing core modules...")
    from parsers.windows_parser import WindowsLogParser
    from parsers.linux_parser import LinuxLogParser
    from detectors.behavior_detector import BehaviorDetector
    print("✅ All core modules imported successfully!")
    
    print("\n🎉 All components are ready for PyCharm!")
    print("You can now:")
    print("1. Open the threat_hunter folder in PyCharm")
    print("2. Run 'python demo.py' to see the demo")
    print("3. Run 'python threat_hunter.py --gui' to launch GUI")
    print("4. Run 'python threat_hunter.py --help' for CLI options")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Please ensure all requirements are installed:")
    print("pip install -r requirements.txt")
except Exception as e:
    print(f"❌ Error: {e}")
    print("There might be an issue with the installation.")
