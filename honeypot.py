#!/usr/bin/env python3
"""
Honeypot System - A comprehensive cybersecurity honeypot implementation
Designed to attract, detect, and analyze unauthorized or malicious activity
"""

import os
import sys
import time
import json
import logging
import threading
import socket
import hashlib
from datetime import datetime
from typing import Dict, List, Any
import signal

# Import our honeypot modules
from modules.web_honeypot import WebHoneypot
from modules.ssh_honeypot import SSHHoneypot
from modules.database_honeypot import DatabaseHoneypot
from modules.monitoring import MonitoringSystem
from modules.logger import HoneypotLogger
from modules.isolation import NetworkIsolation

class HoneypotSystem:
    """
    Main Honeypot System Class
    Coordinates all honeypot components and services
    """
    
    def __init__(self, config_file: str = "config.json"):
        """Initialize the honeypot system"""
        self.config = self.load_config(config_file)
        self.logger = HoneypotLogger(self.config.get('logging', {}))
        self.monitoring = MonitoringSystem(self.config.get('monitoring', {}))
        self.isolation = NetworkIsolation(self.config.get('isolation', {}))
        
        # Initialize honeypot services
        self.services = {}
        self.running = False
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        self.logger.log_system_event("Honeypot system initialized")
    
    def load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Return default configuration
            return self.get_default_config()
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            "honeypot": {
                "name": "CyberHoneypot",
                "type": "low-interaction",
                "description": "A comprehensive honeypot system"
            },
            "services": {
                "web": {
                    "enabled": True,
                    "port": 8080,
                    "host": "0.0.0.0"
                },
                "ssh": {
                    "enabled": True,
                    "port": 2222,
                    "host": "0.0.0.0"
                },
                "database": {
                    "enabled": True,
                    "port": 3306,
                    "host": "0.0.0.0"
                }
            },
            "logging": {
                "level": "INFO",
                "file": "honeypot.log",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            },
            "monitoring": {
                "enabled": True,
                "packet_capture": True,
                "file_integrity": True,
                "process_monitoring": True
            },
            "isolation": {
                "enabled": True,
                "restrict_outbound": True,
                "allowed_ports": [80, 443, 53]
            }
        }
    
    def initialize_services(self):
        """Initialize all honeypot services"""
        self.logger.log_system_event("Initializing honeypot services...")
        
        # Initialize Web Honeypot
        if self.config['services']['web']['enabled']:
            self.services['web'] = WebHoneypot(
                host=self.config['services']['web']['host'],
                port=self.config['services']['web']['port'],
                logger=self.logger,
                monitoring=self.monitoring
            )
        
        # Initialize SSH Honeypot
        if self.config['services']['ssh']['enabled']:
            self.services['ssh'] = SSHHoneypot(
                host=self.config['services']['ssh']['host'],
                port=self.config['services']['ssh']['port'],
                logger=self.logger,
                monitoring=self.monitoring
            )
        
        # Initialize Database Honeypot
        if self.config['services']['database']['enabled']:
            self.services['database'] = DatabaseHoneypot(
                host=self.config['services']['database']['host'],
                port=self.config['services']['database']['port'],
                logger=self.logger,
                monitoring=self.monitoring
            )
        
        self.logger.log_system_event(f"Initialized {len(self.services)} services")
    
    def start_services(self):
        """Start all honeypot services"""
        self.logger.log_system_event("Starting honeypot services...")
        
        for service_name, service in self.services.items():
            try:
                service.start()
                self.logger.log_system_event(f"Started {service_name} service on port {service.port}")
            except Exception as e:
                self.logger.log_error(f"Failed to start {service_name} service: {str(e)}")
        
        self.running = True
        self.logger.log_system_event("All services started successfully")
    
    def stop_services(self):
        """Stop all honeypot services"""
        self.logger.log_system_event("Stopping honeypot services...")
        
        for service_name, service in self.services.items():
            try:
                service.stop()
                self.logger.log_system_event(f"Stopped {service_name} service")
            except Exception as e:
                self.logger.log_error(f"Error stopping {service_name} service: {str(e)}")
        
        self.running = False
        self.logger.log_system_event("All services stopped")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.log_system_event(f"Received signal {signum}, shutting down...")
        self.stop_services()
        sys.exit(0)
    
    def run(self):
        """Main run loop"""
        try:
            # Setup isolation
            if self.config['isolation']['enabled']:
                self.isolation.setup_isolation()
            
            # Initialize and start services
            self.initialize_services()
            self.start_services()
            
            # Start monitoring
            if self.config['monitoring']['enabled']:
                self.monitoring.start()
            
            # Main loop
            self.logger.log_system_event("Honeypot system is running...")
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.log_system_event("Received keyboard interrupt")
        except Exception as e:
            self.logger.log_error(f"Unexpected error: {str(e)}")
        finally:
            self.stop_services()
            if self.config['monitoring']['enabled']:
                self.monitoring.stop()

def main():
    """Main entry point"""
    print("🐝 Starting Honeypot System...")
    print("=" * 50)
    
    # Create config file if it doesn't exist
    if not os.path.exists("config.json"):
        honeypot = HoneypotSystem()
        with open("config.json", 'w') as f:
            json.dump(honeypot.config, f, indent=4)
        print("Created default config.json file")
    
    # Start the honeypot system
    honeypot = HoneypotSystem()
    honeypot.run()

if __name__ == "__main__":
    main()
