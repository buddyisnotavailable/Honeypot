"""
Network Isolation Module
Ensures honeypot is properly isolated from real network to prevent
it from being used to attack other systems
"""

import os
import sys
import subprocess
import platform
import socket
import threading
import time
from typing import Dict, Any, List, Optional
from datetime import datetime

class NetworkIsolation:
    """
    Network isolation system to prevent honeypot from being used
    to attack other systems
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize network isolation"""
        self.config = config
        self.isolation_enabled = False
        self.original_routes = []
        self.original_iptables = []
        self.isolation_thread = None
        
        # Isolation settings
        self.restrict_outbound = config.get('restrict_outbound', True)
        self.allowed_ports = config.get('allowed_ports', [80, 443, 53])
        self.allowed_hosts = config.get('allowed_hosts', [])
        self.blocked_ports = config.get('blocked_ports', [22, 23, 25, 53, 80, 443, 993, 995])
        
    def setup_isolation(self):
        """Setup network isolation"""
        if not self.config.get('enabled', True):
            return
        
        try:
            # Detect operating system
            os_type = platform.system().lower()
            
            if os_type == 'linux':
                self._setup_linux_isolation()
            elif os_type == 'windows':
                self._setup_windows_isolation()
            elif os_type == 'darwin':  # macOS
                self._setup_macos_isolation()
            else:
                print(f"Unsupported operating system: {os_type}")
                return
            
            self.isolation_enabled = True
            print("Network isolation enabled")
            
            # Start monitoring thread
            self._start_isolation_monitoring()
            
        except Exception as e:
            print(f"Failed to setup network isolation: {e}")
    
    def _setup_linux_isolation(self):
        """Setup isolation on Linux systems"""
        try:
            # Check if running as root
            if os.geteuid() != 0:
                print("Warning: Network isolation requires root privileges on Linux")
                return
            
            # Setup iptables rules
            self._setup_linux_iptables()
            
            # Setup network namespace (if supported)
            self._setup_network_namespace()
            
        except Exception as e:
            print(f"Linux isolation setup error: {e}")
    
    def _setup_linux_iptables(self):
        """Setup iptables rules for isolation"""
        try:
            # Save current iptables rules
            result = subprocess.run(['iptables-save'], capture_output=True, text=True)
            if result.returncode == 0:
                self.original_iptables = result.stdout
            
            # Create custom chain for honeypot
            subprocess.run(['iptables', '-N', 'HONEYPOT'], check=True)
            subprocess.run(['iptables', '-A', 'INPUT', '-j', 'HONEYPOT'], check=True)
            subprocess.run(['iptables', '-A', 'OUTPUT', '-j', 'HONEYPOT'], check=True)
            
            # Allow honeypot services
            honeypot_ports = [8080, 2222, 3306]  # Web, SSH, Database
            for port in honeypot_ports:
                subprocess.run(['iptables', '-A', 'HONEYPOT', '-p', 'tcp', 
                              '--dport', str(port), '-j', 'ACCEPT'], check=True)
            
            # Allow DNS resolution
            subprocess.run(['iptables', '-A', 'HONEYPOT', '-p', 'udp', 
                          '--dport', '53', '-j', 'ACCEPT'], check=True)
            
            # Block outbound connections to other systems
            if self.restrict_outbound:
                subprocess.run(['iptables', '-A', 'HONEYPOT', '-d', '10.0.0.0/8', 
                              '-j', 'DROP'], check=True)
                subprocess.run(['iptables', '-A', 'HONEYPOT', '-d', '172.16.0.0/12', 
                              '-j', 'DROP'], check=True)
                subprocess.run(['iptables', '-A', 'HONEYPOT', '-d', '192.168.0.0/16', 
                              '-j', 'DROP'], check=True)
            
            # Allow only specific outbound connections
            for port in self.allowed_ports:
                subprocess.run(['iptables', '-A', 'HONEYPOT', '-p', 'tcp', 
                              '--dport', str(port), '-j', 'ACCEPT'], check=True)
            
            # Drop all other outbound connections
            subprocess.run(['iptables', '-A', 'HONEYPOT', '-j', 'DROP'], check=True)
            
        except subprocess.CalledProcessError as e:
            print(f"iptables setup error: {e}")
        except FileNotFoundError:
            print("iptables not found - isolation may not work properly")
    
    def _setup_network_namespace(self):
        """Setup network namespace for isolation"""
        try:
            # Create network namespace
            subprocess.run(['ip', 'netns', 'add', 'honeypot'], check=True)
            
            # Create virtual interface
            subprocess.run(['ip', 'link', 'add', 'veth0', 'type', 'veth', 
                          'peer', 'name', 'veth1'], check=True)
            
            # Move one end to namespace
            subprocess.run(['ip', 'link', 'set', 'veth1', 'netns', 'honeypot'], check=True)
            
            # Configure interfaces
            subprocess.run(['ip', 'addr', 'add', '10.0.0.1/24', 'dev', 'veth0'], check=True)
            subprocess.run(['ip', 'link', 'set', 'veth0', 'up'], check=True)
            
            subprocess.run(['ip', 'netns', 'exec', 'honeypot', 'ip', 'addr', 
                          'add', '10.0.0.2/24', 'dev', 'veth1'], check=True)
            subprocess.run(['ip', 'netns', 'exec', 'honeypot', 'ip', 'link', 
                          'set', 'veth1', 'up'], check=True)
            
            # Setup routing
            subprocess.run(['ip', 'netns', 'exec', 'honeypot', 'ip', 'route', 
                          'add', 'default', 'via', '10.0.0.1'], check=True)
            
        except subprocess.CalledProcessError as e:
            print(f"Network namespace setup error: {e}")
        except FileNotFoundError:
            print("ip command not found - network namespace isolation not available")
    
    def _setup_windows_isolation(self):
        """Setup isolation on Windows systems"""
        try:
            # Check if running as administrator
            if not self._is_admin():
                print("Warning: Network isolation requires administrator privileges on Windows")
                return
            
            # Setup Windows Firewall rules
            self._setup_windows_firewall()
            
            # Setup network isolation
            self._setup_windows_network_isolation()
            
        except Exception as e:
            print(f"Windows isolation setup error: {e}")
    
    def _is_admin(self) -> bool:
        """Check if running as administrator on Windows"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def _setup_windows_firewall(self):
        """Setup Windows Firewall rules"""
        try:
            # Create firewall rule for honeypot
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=Honeypot Isolation',
                'dir=out',
                'action=block',
                'protocol=any',
                'remoteip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'
            ], check=True)
            
            # Allow DNS
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=Honeypot DNS',
                'dir=out',
                'action=allow',
                'protocol=udp',
                'remoteport=53'
            ], check=True)
            
        except subprocess.CalledProcessError as e:
            print(f"Windows Firewall setup error: {e}")
    
    def _setup_windows_network_isolation(self):
        """Setup Windows network isolation"""
        try:
            # Disable network discovery
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'set', 'rule',
                'group=Network Discovery', 'new', 'enable=no'
            ], check=True)
            
            # Disable file and printer sharing
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'set', 'rule',
                'group=File and Printer Sharing', 'new', 'enable=no'
            ], check=True)
            
        except subprocess.CalledProcessError as e:
            print(f"Windows network isolation setup error: {e}")
    
    def _setup_macos_isolation(self):
        """Setup isolation on macOS systems"""
        try:
            # Check if running as root
            if os.geteuid() != 0:
                print("Warning: Network isolation requires root privileges on macOS")
                return
            
            # Setup pfctl rules
            self._setup_macos_pfctl()
            
        except Exception as e:
            print(f"macOS isolation setup error: {e}")
    
    def _setup_macos_pfctl(self):
        """Setup pfctl rules for macOS"""
        try:
            # Create pfctl configuration
            pfctl_config = """
# Honeypot isolation rules
block out quick on any to 10.0.0.0/8
block out quick on any to 172.16.0.0/12
block out quick on any to 192.168.0.0/16
pass out quick on any to any port 53
pass out quick on any to any port 80
pass out quick on any to any port 443
block out quick on any
"""
            
            # Write configuration to file
            with open('/tmp/honeypot.pfctl', 'w') as f:
                f.write(pfctl_config)
            
            # Load pfctl rules
            subprocess.run(['pfctl', '-f', '/tmp/honeypot.pfctl'], check=True)
            subprocess.run(['pfctl', '-e'], check=True)
            
        except subprocess.CalledProcessError as e:
            print(f"pfctl setup error: {e}")
        except FileNotFoundError:
            print("pfctl not found - isolation may not work properly")
    
    def _start_isolation_monitoring(self):
        """Start monitoring isolation status"""
        self.isolation_thread = threading.Thread(
            target=self._monitor_isolation,
            daemon=True
        )
        self.isolation_thread.start()
    
    def _monitor_isolation(self):
        """Monitor isolation status"""
        while self.isolation_enabled:
            try:
                # Check if isolation rules are still active
                if not self._check_isolation_status():
                    print("Warning: Isolation rules may have been modified")
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                print(f"Isolation monitoring error: {e}")
                time.sleep(30)
    
    def _check_isolation_status(self) -> bool:
        """Check if isolation rules are still active"""
        try:
            os_type = platform.system().lower()
            
            if os_type == 'linux':
                return self._check_linux_isolation()
            elif os_type == 'windows':
                return self._check_windows_isolation()
            elif os_type == 'darwin':
                return self._check_macos_isolation()
            
            return True
            
        except Exception as e:
            print(f"Isolation status check error: {e}")
            return False
    
    def _check_linux_isolation(self) -> bool:
        """Check Linux isolation status"""
        try:
            result = subprocess.run(['iptables', '-L', 'HONEYPOT'], 
                                  capture_output=True, text=True)
            return result.returncode == 0 and 'HONEYPOT' in result.stdout
        except:
            return False
    
    def _check_windows_isolation(self) -> bool:
        """Check Windows isolation status"""
        try:
            result = subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'show', 'rule',
                'name=Honeypot Isolation'
            ], capture_output=True, text=True)
            return result.returncode == 0 and 'Honeypot Isolation' in result.stdout
        except:
            return False
    
    def _check_macos_isolation(self) -> bool:
        """Check macOS isolation status"""
        try:
            result = subprocess.run(['pfctl', '-s', 'rules'], 
                                  capture_output=True, text=True)
            return result.returncode == 0 and 'honeypot' in result.stdout.lower()
        except:
            return False
    
    def disable_isolation(self):
        """Disable network isolation"""
        if not self.isolation_enabled:
            return
        
        try:
            os_type = platform.system().lower()
            
            if os_type == 'linux':
                self._disable_linux_isolation()
            elif os_type == 'windows':
                self._disable_windows_isolation()
            elif os_type == 'darwin':
                self._disable_macos_isolation()
            
            self.isolation_enabled = False
            print("Network isolation disabled")
            
        except Exception as e:
            print(f"Failed to disable isolation: {e}")
    
    def _disable_linux_isolation(self):
        """Disable Linux isolation"""
        try:
            # Remove honeypot chain
            subprocess.run(['iptables', '-D', 'INPUT', '-j', 'HONEYPOT'], 
                         capture_output=True)
            subprocess.run(['iptables', '-D', 'OUTPUT', '-j', 'HONEYPOT'], 
                         capture_output=True)
            subprocess.run(['iptables', '-F', 'HONEYPOT'], capture_output=True)
            subprocess.run(['iptables', '-X', 'HONEYPOT'], capture_output=True)
            
            # Remove network namespace
            subprocess.run(['ip', 'netns', 'del', 'honeypot'], capture_output=True)
            
        except Exception as e:
            print(f"Linux isolation disable error: {e}")
    
    def _disable_windows_isolation(self):
        """Disable Windows isolation"""
        try:
            # Remove firewall rules
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                'name=Honeypot Isolation'
            ], capture_output=True)
            
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                'name=Honeypot DNS'
            ], capture_output=True)
            
        except Exception as e:
            print(f"Windows isolation disable error: {e}")
    
    def _disable_macos_isolation(self):
        """Disable macOS isolation"""
        try:
            # Disable pfctl
            subprocess.run(['pfctl', '-d'], capture_output=True)
            
        except Exception as e:
            print(f"macOS isolation disable error: {e}")
    
    def get_isolation_status(self) -> Dict[str, Any]:
        """Get isolation status information"""
        return {
            'enabled': self.isolation_enabled,
            'restrict_outbound': self.restrict_outbound,
            'allowed_ports': self.allowed_ports,
            'blocked_ports': self.blocked_ports,
            'status': self._check_isolation_status()
        }
