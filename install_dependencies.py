#!/usr/bin/env python3
"""
Dependency Installation Script
Installs required dependencies for the honeypot system
"""

import subprocess
import sys
import os

def install_package(package):
    """Install a Python package using pip"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        return True
    except subprocess.CalledProcessError:
        return False

def check_package(package):
    """Check if a package is already installed"""
    try:
        __import__(package)
        return True
    except ImportError:
        return False

def main():
    """Main installation function"""
    print("🐝 Honeypot System - Dependency Installer")
    print("=" * 50)
    
    # List of required packages
    packages = [
        ("flask", "Flask web framework"),
        ("paramiko", "SSH client library"),
        ("psutil", "System and process utilities"),
        ("requests", "HTTP library"),
        ("cryptography", "Cryptographic recipes and primitives"),
        ("pycryptodome", "Cryptographic library"),
        ("watchdog", "File system event monitoring (optional)")
    ]
    
    print("Checking and installing dependencies...\n")
    
    installed_count = 0
    total_count = len(packages)
    
    for package, description in packages:
        print(f"Checking {package} ({description})...")
        
        if check_package(package):
            print(f"✅ {package} is already installed")
            installed_count += 1
        else:
            print(f"📦 Installing {package}...")
            if install_package(package):
                print(f"✅ {package} installed successfully")
                installed_count += 1
            else:
                print(f"❌ Failed to install {package}")
                if package == "watchdog":
                    print("   (This is optional - file monitoring will be disabled)")
    
    print("\n" + "=" * 50)
    print(f"Installation complete: {installed_count}/{total_count} packages installed")
    
    if installed_count == total_count:
        print("🎉 All dependencies installed successfully!")
        print("You can now run the honeypot system with: python start_honeypot.py")
    else:
        print("⚠️  Some packages failed to install.")
        print("The honeypot will still work with reduced functionality.")
        print("You can try installing missing packages manually with:")
        print("pip install <package_name>")

if __name__ == "__main__":
    main()
