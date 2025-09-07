#!/usr/bin/env python3
"""
Honeypot Startup Script
Simple script to start the honeypot system with proper error handling
"""

import os
import sys
import time
import signal
import subprocess
from pathlib import Path

def check_dependencies():
    """Check if all required dependencies are installed"""
    try:
        import flask  # type: ignore
        import paramiko  # type: ignore
        import psutil  # type: ignore
        import watchdog  # type: ignore
        print("✅ All dependencies are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Please install dependencies with: pip install -r requirements.txt")
        return False

def check_permissions():
    """Check if running with appropriate permissions"""
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                print("✅ Running with administrator privileges")
                return True
            else:
                print("⚠️  Not running as administrator - network isolation may not work")
                return False
        except:
            print("⚠️  Could not check administrator privileges")
            return False
    else:  # Linux/macOS
        if os.geteuid() == 0:
            print("✅ Running as root")
            return True
        else:
            print("⚠️  Not running as root - network isolation may not work")
            return False

def create_directories():
    """Create necessary directories"""
    directories = ['logs', 'logs/attacks', 'logs/connections', 'logs/auth']
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    print("✅ Created log directories")

def start_honeypot():
    """Start the honeypot system"""
    print("🐝 Starting Honeypot System...")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        return False
    
    # Check permissions
    check_permissions()
    
    # Create directories
    create_directories()
    
    # Start the honeypot
    try:
        from honeypot import main
        main()
    except KeyboardInterrupt:
        print("\n🛑 Honeypot stopped by user")
    except Exception as e:
        print(f"❌ Error starting honeypot: {e}")
        return False
    
    return True

def start_dashboard():
    """Start the dashboard in a separate process"""
    print("📊 Starting Dashboard...")
    try:
        subprocess.Popen([sys.executable, 'dashboard.py'])
        print("✅ Dashboard started at http://localhost:9090")
        print("   Default login: admin / honeypot123")
    except Exception as e:
        print(f"❌ Error starting dashboard: {e}")

def main():
    """Main startup function"""
    print("🚀 Honeypot System Startup")
    print("=" * 50)
    
    # Check if config exists
    if not os.path.exists('config.json'):
        print("⚠️  config.json not found, creating default configuration...")
        from honeypot import HoneypotSystem
        honeypot = HoneypotSystem()
        import json
        with open('config.json', 'w') as f:
            json.dump(honeypot.config, f, indent=4)
        print("✅ Created default config.json")
    
    # Ask user what to start
    print("\nWhat would you like to start?")
    print("1. Honeypot only")
    print("2. Dashboard only")
    print("3. Both honeypot and dashboard")
    print("4. Exit")
    
    choice = input("\nEnter your choice (1-4): ").strip()
    
    if choice == '1':
        start_honeypot()
    elif choice == '2':
        start_dashboard()
        input("Press Enter to stop dashboard...")
    elif choice == '3':
        start_dashboard()
        time.sleep(2)  # Give dashboard time to start
        start_honeypot()
    elif choice == '4':
        print("👋 Goodbye!")
    else:
        print("❌ Invalid choice")

if __name__ == "__main__":
    main()
