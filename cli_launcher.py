#!/usr/bin/env python3
"""
ThreatHunter CLI Launcher
Simple script to launch ThreatHunter in the best mode for beginners
"""

import sys
from pathlib import Path
from colorama import init, Fore, Style

# Initialize colorama for Windows support
init(autoreset=True)

def main():
    """Simple launcher for ThreatHunter"""
    print(f"{Fore.CYAN}[*] ThreatHunter Quick Launcher{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}=============================={Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}Welcome to ThreatHunter!{Style.RESET_ALL}")
    print(f"This tool analyzes log files to detect suspicious activity.")
    
    print(f"\n{Fore.YELLOW}Choose how you'd like to use ThreatHunter:{Style.RESET_ALL}")
    print(f"  1. [*] Interactive Mode (Recommended for beginners)")
    print(f"  2. [*] Run Demo (See what ThreatHunter can do)")
    print(f"  3. [*] Command Line Help")
    print(f"  4. [*] Exit")
    
    while True:
        try:
            choice = input(f"\n{Fore.CYAN}Enter your choice (1-4): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                print(f"\n{Fore.GREEN}[+] Launching Interactive Mode...{Style.RESET_ALL}")
                import threat_hunter
                th = threat_hunter.ThreatHunter()
                th.print_banner()
                th.interactive_mode()
                break
                
            elif choice == '2':
                print(f"\n{Fore.GREEN}[+] Starting Demo...{Style.RESET_ALL}")
                try:
                    import demo
                    demo.main()
                except ImportError:
                    print(f"{Fore.RED}[!] Demo module not found.{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Demo failed: {str(e)}{Style.RESET_ALL}")
                break
                
            elif choice == '3':
                print(f"\n{Fore.CYAN}[*] Command Line Usage:{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}Basic usage:{Style.RESET_ALL}")
                print(f"    python threat_hunter.py -f logfile.evtx -t windows")
                print(f"    python threat_hunter.py -f /var/log/syslog -t linux")
                print(f"")
                print(f"  {Fore.YELLOW}Interactive mode:{Style.RESET_ALL}")
                print(f"    python threat_hunter.py --interactive")
                print(f"")
                print(f"  {Fore.YELLOW}Output formats:{Style.RESET_ALL}")
                print(f"    python threat_hunter.py -f logfile.evtx -t windows -o json")
                print(f"    python threat_hunter.py -f logfile.evtx -t windows -o csv")
                print(f"")
                print(f"  {Fore.YELLOW}Full help:{Style.RESET_ALL}")
                print(f"    python threat_hunter.py --help")
                break
                
            elif choice == '4':
                print(f"\n{Fore.GREEN}[+] Goodbye!{Style.RESET_ALL}")
                break
                
            else:
                print(f"{Fore.RED}[!] Invalid choice. Please select 1-4.{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[+] Goodbye!{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
