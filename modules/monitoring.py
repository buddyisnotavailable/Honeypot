"""
Monitoring System Module
Comprehensive monitoring for honeypot activities including packet capture,
file integrity monitoring, and process monitoring
"""

import os
import time
import json
import threading
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
import subprocess
import platform

# Try to import optional dependencies
try:
    import psutil  # type: ignore
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not available. Process monitoring will be disabled.")

try:
    from watchdog.observers import Observer  # type: ignore
    from watchdog.events import FileSystemEventHandler  # type: ignore
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("Warning: watchdog not available. File monitoring will be disabled.")

class MonitoringSystem:
    """
    Comprehensive monitoring system for honeypot activities
    Includes packet capture, file integrity monitoring, and process monitoring
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the monitoring system"""
        self.config = config
        self.running = False
        self.monitor_threads = []
        
        # Monitoring components
        self.packet_capture = None
        self.file_monitor = None
        self.process_monitor = None
        
        # Data storage
        self.packet_data = []
        self.file_events = []
        self.process_events = []
        
        # Attack tracking
        self.attack_patterns = {}
        self.suspicious_ips = set()
        self.attack_timeline = []
        
    def start(self):
        """Start all monitoring components"""
        if not self.running:
            self.running = True
            
            # Start packet capture if enabled
            if self.config.get('packet_capture', True):
                self._start_packet_capture()
            
            # Start file integrity monitoring if enabled
            if self.config.get('file_integrity', True):
                self._start_file_monitoring()
            
            # Start process monitoring if enabled
            if self.config.get('process_monitoring', True):
                self._start_process_monitoring()
            
            # Start attack pattern analysis
            self._start_attack_analysis()
    
    def stop(self):
        """Stop all monitoring components"""
        self.running = False
        
        # Stop all monitoring threads
        for thread in self.monitor_threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        # Stop packet capture
        if self.packet_capture:
            self.packet_capture.stop()
        
        # Stop file monitoring
        if self.file_monitor:
            self.file_monitor.stop()
    
    def _start_packet_capture(self):
        """Start packet capture monitoring"""
        try:
            self.packet_capture = PacketCapture(self)
            packet_thread = threading.Thread(
                target=self.packet_capture.start,
                daemon=True
            )
            packet_thread.start()
            self.monitor_threads.append(packet_thread)
        except Exception as e:
            print(f"Failed to start packet capture: {e}")
    
    def _start_file_monitoring(self):
        """Start file integrity monitoring"""
        if not WATCHDOG_AVAILABLE:
            print("File monitoring disabled - watchdog not available")
            return
            
        try:
            self.file_monitor = FileIntegrityMonitor(self)
            file_thread = threading.Thread(
                target=self.file_monitor.start,
                daemon=True
            )
            file_thread.start()
            self.monitor_threads.append(file_thread)
        except Exception as e:
            print(f"Failed to start file monitoring: {e}")
    
    def _start_process_monitoring(self):
        """Start process monitoring"""
        if not PSUTIL_AVAILABLE:
            print("Process monitoring disabled - psutil not available")
            return
            
        try:
            self.process_monitor = ProcessMonitor(self)
            process_thread = threading.Thread(
                target=self.process_monitor.start,
                daemon=True
            )
            process_thread.start()
            self.monitor_threads.append(process_thread)
        except Exception as e:
            print(f"Failed to start process monitoring: {e}")
    
    def _start_attack_analysis(self):
        """Start attack pattern analysis"""
        analysis_thread = threading.Thread(
            target=self._analyze_attack_patterns,
            daemon=True
        )
        analysis_thread.start()
        self.monitor_threads.append(analysis_thread)
    
    def _analyze_attack_patterns(self):
        """Analyze attack patterns and identify suspicious behavior"""
        while self.running:
            try:
                # Analyze recent attacks
                recent_attacks = self.attack_timeline[-100:] if self.attack_timeline else []
                
                # Identify suspicious IPs
                ip_counts = {}
                for attack in recent_attacks:
                    ip = attack.get('source_ip', 'unknown')
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                
                # Mark IPs with multiple attacks as suspicious
                for ip, count in ip_counts.items():
                    if count > 5:  # Threshold for suspicious activity
                        self.suspicious_ips.add(ip)
                
                # Analyze attack patterns
                self._detect_attack_patterns(recent_attacks)
                
                time.sleep(60)  # Analyze every minute
                
            except Exception as e:
                print(f"Attack analysis error: {e}")
                time.sleep(60)
    
    def _detect_attack_patterns(self, attacks: List[Dict[str, Any]]):
        """Detect common attack patterns"""
        if not attacks:
            return
        
        # Group attacks by type
        attack_types = {}
        for attack in attacks:
            attack_type = attack.get('attack_type', 'unknown')
            if attack_type not in attack_types:
                attack_types[attack_type] = []
            attack_types[attack_type].append(attack)
        
        # Detect brute force attacks
        for attack_type, attack_list in attack_types.items():
            if len(attack_list) > 10:  # Threshold for brute force
                self.attack_patterns[f'brute_force_{attack_type}'] = {
                    'pattern': 'brute_force',
                    'attack_type': attack_type,
                    'count': len(attack_list),
                    'timeframe': 'recent',
                    'severity': 'high'
                }
        
        # Detect scanning patterns
        unique_ips = set(attack.get('source_ip', 'unknown') for attack in attacks)
        if len(unique_ips) > 20:  # Many different IPs
            self.attack_patterns['distributed_scanning'] = {
                'pattern': 'distributed_scanning',
                'unique_ips': len(unique_ips),
                'timeframe': 'recent',
                'severity': 'medium'
            }
    
    def log_web_attack(self, attack_type: str, source_ip: str, details: Dict[str, Any]):
        """Log web-based attack"""
        attack_data = {
            'timestamp': datetime.now().isoformat(),
            'service': 'web',
            'attack_type': attack_type,
            'source_ip': source_ip,
            'details': details
        }
        
        self.attack_timeline.append(attack_data)
        self._save_attack_data(attack_data)
    
    def log_ssh_attack(self, attack_type: str, source_ip: str, details: Dict[str, Any]):
        """Log SSH-based attack"""
        attack_data = {
            'timestamp': datetime.now().isoformat(),
            'service': 'ssh',
            'attack_type': attack_type,
            'source_ip': source_ip,
            'details': details
        }
        
        self.attack_timeline.append(attack_data)
        self._save_attack_data(attack_data)
    
    def log_database_attack(self, attack_type: str, source_ip: str, details: Dict[str, Any]):
        """Log database-based attack"""
        attack_data = {
            'timestamp': datetime.now().isoformat(),
            'service': 'database',
            'attack_type': attack_type,
            'source_ip': source_ip,
            'details': details
        }
        
        self.attack_timeline.append(attack_data)
        self._save_attack_data(attack_data)
    
    def _save_attack_data(self, attack_data: Dict[str, Any]):
        """Save attack data to file"""
        try:
            os.makedirs('logs/attacks', exist_ok=True)
            filename = f"attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join('logs/attacks', filename)
            
            with open(filepath, 'w') as f:
                json.dump(attack_data, f, indent=2)
        except Exception as e:
            print(f"Failed to save attack data: {e}")
    
    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        return {
            'packet_capture': {
                'enabled': self.packet_capture is not None,
                'packets_captured': len(self.packet_data)
            },
            'file_monitoring': {
                'enabled': self.file_monitor is not None,
                'file_events': len(self.file_events)
            },
            'process_monitoring': {
                'enabled': self.process_monitor is not None,
                'process_events': len(self.process_events)
            },
            'attack_analysis': {
                'total_attacks': len(self.attack_timeline),
                'suspicious_ips': len(self.suspicious_ips),
                'attack_patterns': len(self.attack_patterns),
                'recent_patterns': list(self.attack_patterns.keys())[-5:]
            }
        }

class PacketCapture:
    """Packet capture for network monitoring"""
    
    def __init__(self, monitoring_system):
        self.monitoring = monitoring_system
        self.running = False
        self.capture_process = None
    
    def start(self):
        """Start packet capture"""
        self.running = True
        
        # Use tcpdump if available
        if self._is_tcpdump_available():
            self._start_tcpdump()
        else:
            # Fallback to basic network monitoring
            self._start_basic_monitoring()
    
    def stop(self):
        """Stop packet capture"""
        self.running = False
        if self.capture_process:
            self.capture_process.terminate()
    
    def _is_tcpdump_available(self) -> bool:
        """Check if tcpdump is available"""
        try:
            subprocess.run(['tcpdump', '--version'], 
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _start_tcpdump(self):
        """Start tcpdump packet capture"""
        try:
            # Start tcpdump to capture packets
            cmd = ['tcpdump', '-i', 'any', '-n', '-s', '0', '-w', 'logs/packets.pcap']
            self.capture_process = subprocess.Popen(cmd)
        except Exception as e:
            print(f"Failed to start tcpdump: {e}")
    
    def _start_basic_monitoring(self):
        """Start basic network monitoring"""
        if not PSUTIL_AVAILABLE:
            print("Basic network monitoring disabled - psutil not available")
            return
            
        while self.running:
            try:
                # Monitor network connections
                connections = psutil.net_connections()
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        self.monitoring.packet_data.append({
                            'timestamp': datetime.now().isoformat(),
                            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "unknown",
                            'status': conn.status
                        })
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                print(f"Basic monitoring error: {e}")
                time.sleep(5)

if WATCHDOG_AVAILABLE:
    class FileIntegrityMonitor(FileSystemEventHandler):
        """File integrity monitoring using watchdog"""
        
        def __init__(self, monitoring_system):
            self.monitoring = monitoring_system
            self.observer = Observer()
            self.running = False
        
        def start(self):
            """Start file monitoring"""
            self.running = True
            
            # Monitor current directory and subdirectories
            self.observer.schedule(self, '.', recursive=True)
            self.observer.start()
        
        def stop(self):
            """Stop file monitoring"""
            self.running = False
            self.observer.stop()
            self.observer.join()
        
        def on_modified(self, event):
            """Handle file modification events"""
            if not event.is_directory:
                self._log_file_event('modified', event.src_path)
        
        def on_created(self, event):
            """Handle file creation events"""
            if not event.is_directory:
                self._log_file_event('created', event.src_path)
        
        def on_deleted(self, event):
            """Handle file deletion events"""
            if not event.is_directory:
                self._log_file_event('deleted', event.src_path)
        
        def _log_file_event(self, event_type: str, file_path: str):
            """Log file system event"""
            event_data = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'file_path': file_path,
                'file_hash': self._calculate_file_hash(file_path) if os.path.exists(file_path) else None
            }
            
            self.monitoring.file_events.append(event_data)
        
        def _calculate_file_hash(self, file_path: str) -> Optional[str]:
            """Calculate file hash for integrity checking"""
            try:
                with open(file_path, 'rb') as f:
                    return hashlib.sha256(f.read()).hexdigest()
            except Exception:
                return None
else:
    class FileIntegrityMonitor:
        """Fallback file integrity monitoring without watchdog"""
        
        def __init__(self, monitoring_system):
            self.monitoring = monitoring_system
            self.running = False
            self.file_hashes = {}
        
        def start(self):
            """Start basic file monitoring"""
            self.running = True
            self._scan_files()
            
            # Monitor files periodically
            while self.running:
                try:
                    self._check_file_changes()
                    time.sleep(30)  # Check every 30 seconds
                except Exception as e:
                    print(f"File monitoring error: {e}")
                    time.sleep(30)
        
        def stop(self):
            """Stop file monitoring"""
            self.running = False
        
        def _scan_files(self):
            """Initial file scan"""
            try:
                for root, dirs, files in os.walk('.'):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if os.path.exists(file_path):
                            self.file_hashes[file_path] = self._calculate_file_hash(file_path)
            except Exception as e:
                print(f"File scan error: {e}")
        
        def _check_file_changes(self):
            """Check for file changes"""
            try:
                current_files = set()
                for root, dirs, files in os.walk('.'):
                    for file in files:
                        file_path = os.path.join(root, file)
                        current_files.add(file_path)
                        
                        if file_path not in self.file_hashes:
                            # New file
                            self._log_file_event('created', file_path)
                        else:
                            # Check if file changed
                            current_hash = self._calculate_file_hash(file_path)
                            if current_hash != self.file_hashes[file_path]:
                                self._log_file_event('modified', file_path)
                        
                        self.file_hashes[file_path] = self._calculate_file_hash(file_path)
                
                # Check for deleted files
                for file_path in list(self.file_hashes.keys()):
                    if file_path not in current_files:
                        self._log_file_event('deleted', file_path)
                        del self.file_hashes[file_path]
                        
            except Exception as e:
                print(f"File change check error: {e}")
        
        def _log_file_event(self, event_type: str, file_path: str):
            """Log file system event"""
            event_data = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'file_path': file_path,
                'file_hash': self._calculate_file_hash(file_path) if os.path.exists(file_path) else None
            }
            
            self.monitoring.file_events.append(event_data)
        
        def _calculate_file_hash(self, file_path: str) -> Optional[str]:
            """Calculate file hash for integrity checking"""
            try:
                with open(file_path, 'rb') as f:
                    return hashlib.sha256(f.read()).hexdigest()
            except Exception:
                return None

if PSUTIL_AVAILABLE:
    class ProcessMonitor:
        """Process monitoring for suspicious activity"""
        
        def __init__(self, monitoring_system):
            self.monitoring = monitoring_system
            self.running = False
            self.known_processes = set()
        
        def start(self):
            """Start process monitoring"""
            self.running = True
            
            # Get initial process list
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    self.known_processes.add(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Monitor for new processes
            while self.running:
                try:
                    current_processes = set()
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        try:
                            pid = proc.info['pid']
                            current_processes.add(pid)
                            
                            # Check for new processes
                            if pid not in self.known_processes:
                                self._log_new_process(proc.info)
                            
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    
                    # Check for terminated processes
                    terminated = self.known_processes - current_processes
                    for pid in terminated:
                        self._log_terminated_process(pid)
                    
                    self.known_processes = current_processes
                    time.sleep(10)  # Check every 10 seconds
                    
                except Exception as e:
                    print(f"Process monitoring error: {e}")
                    time.sleep(10)
        
        def _log_new_process(self, proc_info: Dict[str, Any]):
            """Log new process creation"""
            event_data = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'process_created',
                'pid': proc_info['pid'],
                'name': proc_info['name'],
                'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
            }
            
            self.monitoring.process_events.append(event_data)
        
        def _log_terminated_process(self, pid: int):
            """Log process termination"""
            event_data = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'process_terminated',
                'pid': pid
            }
            
            self.monitoring.process_events.append(event_data)
else:
    class ProcessMonitor:
        """Fallback process monitoring without psutil"""
        
        def __init__(self, monitoring_system):
            self.monitoring = monitoring_system
            self.running = False
        
        def start(self):
            """Start basic process monitoring"""
            self.running = True
            print("Process monitoring disabled - psutil not available")
            
            # Just sleep to keep the thread alive
            while self.running:
                time.sleep(10)
