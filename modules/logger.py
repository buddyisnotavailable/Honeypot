"""
Honeypot Logging System
Comprehensive logging for all honeypot activities and security events
"""

import os
import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional

class HoneypotLogger:
    """
    Advanced logging system for honeypot activities
    Logs all interactions, attacks, and system events
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the logging system"""
        self.config = config
        self.setup_logging()
        self.attack_logs = []
        self.session_logs = {}
        
    def setup_logging(self):
        """Setup logging configuration"""
        log_level = getattr(logging, self.config.get('level', 'INFO').upper())
        log_file = self.config.get('file', 'honeypot.log')
        
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        log_path = os.path.join('logs', log_file)
        
        # Setup formatter
        formatter = logging.Formatter(
            self.config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        
        # Setup file handler
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(formatter)
        
        # Setup console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        # Setup logger
        self.logger = logging.getLogger('Honeypot')
        self.logger.setLevel(log_level)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Prevent duplicate logs
        self.logger.propagate = False
    
    def log_attack(self, attack_type: str, source_ip: str, details: Dict[str, Any]):
        """Log attack attempts with detailed information"""
        attack_data = {
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_type,
            'source_ip': source_ip,
            'details': details,
            'session_id': self.generate_session_id(source_ip)
        }
        
        # Add to attack logs
        self.attack_logs.append(attack_data)
        
        # Log to file
        self.logger.warning(f"ATTACK DETECTED: {attack_type} from {source_ip}")
        self.logger.info(f"Attack details: {json.dumps(details, indent=2)}")
        
        # Save to JSON file for analysis
        self.save_attack_log(attack_data)
    
    def log_connection(self, service: str, source_ip: str, port: int, details: Dict[str, Any]):
        """Log connection attempts"""
        connection_data = {
            'timestamp': datetime.now().isoformat(),
            'service': service,
            'source_ip': source_ip,
            'port': port,
            'details': details
        }
        
        self.logger.info(f"CONNECTION: {service} from {source_ip}:{port}")
        self.logger.debug(f"Connection details: {json.dumps(details, indent=2)}")
        
        # Save connection log
        self.save_connection_log(connection_data)
    
    def log_authentication_attempt(self, service: str, source_ip: str, username: str, 
                                 password: str, success: bool):
        """Log authentication attempts"""
        auth_data = {
            'timestamp': datetime.now().isoformat(),
            'service': service,
            'source_ip': source_ip,
            'username': username,
            'password': password,
            'success': success,
            'password_hash': hashlib.sha256(password.encode()).hexdigest()
        }
        
        status = "SUCCESS" if success else "FAILED"
        self.logger.warning(f"AUTH {status}: {service} - {username} from {source_ip}")
        
        # Save authentication log
        self.save_auth_log(auth_data)
    
    def log_system_event(self, message: str, level: str = "INFO"):
        """Log system events"""
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(f"SYSTEM: {message}")
    
    def log_error(self, message: str, exception: Optional[Exception] = None):
        """Log errors with optional exception details"""
        if exception:
            self.logger.error(f"ERROR: {message} - {str(exception)}", exc_info=True)
        else:
            self.logger.error(f"ERROR: {message}")
    
    def generate_session_id(self, source_ip: str) -> str:
        """Generate a unique session ID for tracking"""
        timestamp = datetime.now().isoformat()
        return hashlib.md5(f"{source_ip}_{timestamp}".encode()).hexdigest()[:16]
    
    def save_attack_log(self, attack_data: Dict[str, Any]):
        """Save attack log to JSON file"""
        os.makedirs('logs/attacks', exist_ok=True)
        filename = f"attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join('logs/attacks', filename)
        
        with open(filepath, 'w') as f:
            json.dump(attack_data, f, indent=2)
    
    def save_connection_log(self, connection_data: Dict[str, Any]):
        """Save connection log to JSON file"""
        os.makedirs('logs/connections', exist_ok=True)
        filename = f"connection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join('logs/connections', filename)
        
        with open(filepath, 'w') as f:
            json.dump(connection_data, f, indent=2)
    
    def save_auth_log(self, auth_data: Dict[str, Any]):
        """Save authentication log to JSON file"""
        os.makedirs('logs/auth', exist_ok=True)
        filename = f"auth_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join('logs/auth', filename)
        
        with open(filepath, 'w') as f:
            json.dump(auth_data, f, indent=2)
    
    def get_attack_summary(self) -> Dict[str, Any]:
        """Get summary of all attacks"""
        if not self.attack_logs:
            return {"total_attacks": 0, "attack_types": {}, "source_ips": []}
        
        attack_types = {}
        source_ips = set()
        
        for attack in self.attack_logs:
            attack_type = attack['attack_type']
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            source_ips.add(attack['source_ip'])
        
        return {
            "total_attacks": len(self.attack_logs),
            "attack_types": attack_types,
            "source_ips": list(source_ips),
            "latest_attack": self.attack_logs[-1] if self.attack_logs else None
        }
