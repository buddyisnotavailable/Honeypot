#!/usr/bin/env python3
"""
Honeypot Test Script
Tests all components of the honeypot system
"""

import requests
import socket
import time
import json
import os
from datetime import datetime

def test_web_honeypot():
    """Test web honeypot functionality"""
    print("🌐 Testing Web Honeypot...")
    
    try:
        # Test main page
        response = requests.get('http://localhost:8080', timeout=5)
        if response.status_code == 200:
            print("✅ Web honeypot main page accessible")
        else:
            print(f"❌ Web honeypot main page failed: {response.status_code}")
            return False
        
        # Test admin panel
        response = requests.get('http://localhost:8080/admin', timeout=5)
        if response.status_code == 200:
            print("✅ Admin panel accessible")
        else:
            print(f"❌ Admin panel failed: {response.status_code}")
            return False
        
        # Test fake login attempt
        login_data = {'username': 'admin', 'password': 'password123'}
        response = requests.post('http://localhost:8080/admin/login', data=login_data, timeout=5)
        if response.status_code == 200:
            print("✅ Login attempt logged successfully")
        else:
            print(f"❌ Login attempt failed: {response.status_code}")
            return False
        
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Web honeypot test failed: {e}")
        return False

def test_ssh_honeypot():
    """Test SSH honeypot functionality"""
    print("🔐 Testing SSH Honeypot...")
    
    try:
        # Test SSH connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(('localhost', 2222))
        sock.close()
        
        if result == 0:
            print("✅ SSH honeypot port accessible")
            return True
        else:
            print(f"❌ SSH honeypot port not accessible: {result}")
            return False
            
    except Exception as e:
        print(f"❌ SSH honeypot test failed: {e}")
        return False

def test_database_honeypot():
    """Test database honeypot functionality"""
    print("🗄️ Testing Database Honeypot...")
    
    try:
        # Test database connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(('localhost', 3306))
        sock.close()
        
        if result == 0:
            print("✅ Database honeypot port accessible")
            return True
        else:
            print(f"❌ Database honeypot port not accessible: {result}")
            return False
            
    except Exception as e:
        print(f"❌ Database honeypot test failed: {e}")
        return False

def test_logging():
    """Test logging functionality"""
    print("📝 Testing Logging System...")
    
    try:
        # Check if log files exist
        log_files = [
            'logs/honeypot.log',
            'logs/attacks/',
            'logs/connections/',
            'logs/auth/'
        ]
        
        for log_file in log_files:
            if os.path.exists(log_file):
                print(f"✅ {log_file} exists")
            else:
                print(f"❌ {log_file} missing")
                return False
        
        # Check if main log has content
        if os.path.exists('logs/honeypot.log'):
            with open('logs/honeypot.log', 'r') as f:
                content = f.read()
                if len(content) > 0:
                    print("✅ Main log file has content")
                else:
                    print("❌ Main log file is empty")
                    return False
        
        return True
        
    except Exception as e:
        print(f"❌ Logging test failed: {e}")
        return False

def test_configuration():
    """Test configuration system"""
    print("⚙️ Testing Configuration System...")
    
    try:
        # Check if config file exists
        if os.path.exists('config.json'):
            print("✅ Configuration file exists")
            
            # Load and validate config
            with open('config.json', 'r') as f:
                config = json.load(f)
            
            required_sections = ['honeypot', 'services', 'logging', 'monitoring', 'isolation']
            for section in required_sections:
                if section in config:
                    print(f"✅ Configuration section '{section}' present")
                else:
                    print(f"❌ Configuration section '{section}' missing")
                    return False
            
            return True
        else:
            print("❌ Configuration file missing")
            return False
            
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test_dependencies():
    """Test if all dependencies are available"""
    print("📦 Testing Dependencies...")
    
    dependencies = [
        'flask',
        'paramiko', 
        'psutil',
        'requests',
        'cryptography',
        'pycryptodome'
    ]
    
    optional_dependencies = [
        'watchdog'
    ]
    
    all_good = True
    
    for dep in dependencies:
        try:
            __import__(dep)
            print(f"✅ {dep} available")
        except ImportError:
            print(f"❌ {dep} missing (required)")
            all_good = False
    
    for dep in optional_dependencies:
        try:
            __import__(dep)
            print(f"✅ {dep} available (optional)")
        except ImportError:
            print(f"⚠️ {dep} missing (optional - fallback available)")
    
    return all_good

def main():
    """Main test function"""
    print("🧪 Honeypot System Test Suite")
    print("=" * 50)
    print(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    tests = [
        ("Dependencies", test_dependencies),
        ("Configuration", test_configuration),
        ("Logging", test_logging),
        ("Web Honeypot", test_web_honeypot),
        ("SSH Honeypot", test_ssh_honeypot),
        ("Database Honeypot", test_database_honeypot)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:20} {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Honeypot system is ready to use.")
    else:
        print("⚠️ Some tests failed. Check the output above for details.")
    
    print(f"\nTest completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
