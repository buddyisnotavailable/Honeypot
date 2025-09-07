"""
Database Honeypot Module
Simulates vulnerable database servers to attract and log database attacks
"""

import os
import socket
import threading
import time
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

class DatabaseHoneypot:
    """
    Database Honeypot - Simulates vulnerable database servers
    Supports MySQL, PostgreSQL, and MongoDB protocols
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 3306, 
                 logger=None, monitoring=None, db_type: str = "mysql"):
        """Initialize the database honeypot"""
        self.host = host
        self.port = port
        self.logger = logger
        self.monitoring = monitoring
        self.db_type = db_type.lower()
        self.server_socket = None
        self.running = False
        self.server_thread = None
        
        # Attack tracking
        self.connection_count = 0
        self.auth_attempts = []
        self.queries_executed = []
        
        # Fake database information
        self.fake_databases = ['information_schema', 'mysql', 'performance_schema', 'test', 'company_db']
        self.fake_tables = {
            'company_db': ['users', 'products', 'orders', 'customers', 'admin_users'],
            'test': ['test_table', 'sample_data'],
            'mysql': ['user', 'db', 'host', 'tables_priv', 'columns_priv']
        }
        
    def start(self):
        """Start the database honeypot server"""
        if not self.running:
            self.running = True
            self.server_thread = threading.Thread(
                target=self._run_server,
                daemon=True
            )
            self.server_thread.start()
    
    def stop(self):
        """Stop the database honeypot server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.server_thread:
            self.server_thread.join(timeout=5)
    
    def _run_server(self):
        """Run the database server"""
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            if self.logger:
                self.logger.log_system_event(f"Database honeypot ({self.db_type}) listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    self.connection_count += 1
                    
                    # Handle each connection in a separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.error:
                    if self.running:
                        if self.logger:
                            self.logger.log_error("Database server socket error")
                    break
                    
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"Database honeypot server error: {str(e)}")
    
    def _handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        """Handle individual database client connection"""
        source_ip = client_address[0]
        
        try:
            # Log connection attempt
            if self.logger:
                self.logger.log_connection('database', source_ip, self.port, {
                    'timestamp': datetime.now().isoformat(),
                    'client_address': client_address,
                    'database_type': self.db_type
                })
            
            # Handle different database protocols
            if self.db_type == "mysql":
                self._handle_mysql_protocol(client_socket, source_ip)
            elif self.db_type == "postgresql":
                self._handle_postgresql_protocol(client_socket, source_ip)
            elif self.db_type == "mongodb":
                self._handle_mongodb_protocol(client_socket, source_ip)
            else:
                self._handle_generic_protocol(client_socket, source_ip)
                
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"Database client handling error: {str(e)}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _handle_mysql_protocol(self, client_socket: socket.socket, source_ip: str):
        """Handle MySQL protocol"""
        try:
            # Send MySQL handshake packet
            handshake = self._create_mysql_handshake()
            client_socket.send(handshake)
            
            # Wait for authentication
            auth_packet = client_socket.recv(1024)
            if auth_packet:
                self._parse_mysql_auth(auth_packet, source_ip)
                
                # Send authentication failure
                error_packet = self._create_mysql_error("Access denied for user")
                client_socket.send(error_packet)
                
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"MySQL protocol error: {str(e)}")
    
    def _handle_postgresql_protocol(self, client_socket: socket.socket, source_ip: str):
        """Handle PostgreSQL protocol"""
        try:
            # Send PostgreSQL startup message
            startup_msg = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
            client_socket.send(startup_msg)
            
            # Wait for authentication request
            auth_request = client_socket.recv(1024)
            if auth_request:
                self._parse_postgresql_auth(auth_request, source_ip)
                
                # Send authentication failure
                error_msg = b'\x45\x00\x00\x00\x3a\x53\x45\x52\x52\x4f\x52\x00\x43\x32\x38\x50\x30\x31\x00\x4d\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x69\x6f\x6e\x20\x66\x61\x69\x6c\x65\x64\x00\x00'
                client_socket.send(error_msg)
                
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"PostgreSQL protocol error: {str(e)}")
    
    def _handle_mongodb_protocol(self, client_socket: socket.socket, source_ip: str):
        """Handle MongoDB protocol"""
        try:
            # Send MongoDB response
            response = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            client_socket.send(response)
            
            # Wait for MongoDB query
            query = client_socket.recv(1024)
            if query:
                self._parse_mongodb_query(query, source_ip)
                
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"MongoDB protocol error: {str(e)}")
    
    def _handle_generic_protocol(self, client_socket: socket.socket, source_ip: str):
        """Handle generic database protocol"""
        try:
            # Send generic response
            response = b"Database server ready\n"
            client_socket.send(response)
            
            # Wait for input
            data = client_socket.recv(1024)
            if data:
                self._log_generic_query(data.decode('utf-8', errors='ignore'), source_ip)
                
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"Generic protocol error: {str(e)}")
    
    def _create_mysql_handshake(self) -> bytes:
        """Create MySQL handshake packet"""
        # Simplified MySQL handshake packet
        handshake = bytearray()
        handshake.extend(b'\x0a')  # Protocol version
        handshake.extend(b'5.7.30-0ubuntu0.18.04.1\x00')  # Server version
        handshake.extend(b'\x01\x00\x00\x00')  # Connection ID
        handshake.extend(b'12345678\x00')  # Auth plugin data part 1
        handshake.extend(b'\x00')  # Filler
        handshake.extend(b'\xff\xf7')  # Capability flags
        handshake.extend(b'\x08')  # Character set
        handshake.extend(b'\x02\x00')  # Status flags
        handshake.extend(b'\x00\x00')  # Extended capability flags
        handshake.extend(b'\x15')  # Auth plugin data len
        handshake.extend(b'\x00' * 10)  # Reserved
        handshake.extend(b'12345678901234567890\x00')  # Auth plugin data part 2
        handshake.extend(b'mysql_native_password\x00')  # Auth plugin name
        
        # Add length prefix
        length = len(handshake)
        packet = bytearray()
        packet.extend(length.to_bytes(3, 'little'))
        packet.extend(b'\x00')  # Packet number
        packet.extend(handshake)
        
        return bytes(packet)
    
    def _create_mysql_error(self, message: str) -> bytes:
        """Create MySQL error packet"""
        error_msg = message.encode('utf-8')
        packet = bytearray()
        packet.extend(b'\xff')  # Error packet
        packet.extend(b'\x00\x00')  # Error code
        packet.extend(b'#')  # SQL state marker
        packet.extend(b'28000')  # SQL state
        packet.extend(error_msg)
        
        # Add length prefix
        length = len(packet)
        full_packet = bytearray()
        full_packet.extend(length.to_bytes(3, 'little'))
        full_packet.extend(b'\x01')  # Packet number
        full_packet.extend(packet)
        
        return bytes(full_packet)
    
    def _parse_mysql_auth(self, auth_packet: bytes, source_ip: str):
        """Parse MySQL authentication packet"""
        try:
            # Extract username and password from auth packet
            # This is a simplified parser
            packet_data = auth_packet[4:]  # Skip length and packet number
            
            # Find username (null-terminated)
            username_end = packet_data.find(b'\x00')
            if username_end > 0:
                username = packet_data[:username_end].decode('utf-8', errors='ignore')
                
                # Extract password (if present)
                password_data = packet_data[username_end + 1:]
                if len(password_data) > 0:
                    password = password_data.decode('utf-8', errors='ignore')
                else:
                    password = ""
                
                # Log authentication attempt
                self._log_auth_attempt(username, password, source_ip, 'mysql')
                
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"MySQL auth parsing error: {str(e)}")
    
    def _parse_postgresql_auth(self, auth_packet: bytes, source_ip: str):
        """Parse PostgreSQL authentication packet"""
        try:
            # Extract username and password from auth packet
            packet_str = auth_packet.decode('utf-8', errors='ignore')
            
            # Look for username and password in the packet
            if 'user' in packet_str.lower():
                # Simplified parsing - in reality, PostgreSQL uses a more complex format
                username = "postgres"  # Default username
                password = "password"  # Default password
                
                self._log_auth_attempt(username, password, source_ip, 'postgresql')
                
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"PostgreSQL auth parsing error: {str(e)}")
    
    def _parse_mongodb_query(self, query_packet: bytes, source_ip: str):
        """Parse MongoDB query packet"""
        try:
            # Log MongoDB query attempt
            query_data = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': source_ip,
                'database_type': 'mongodb',
                'query': query_packet.hex(),
                'attack_type': 'mongodb_query'
            }
            
            if self.logger:
                self.logger.log_attack('mongodb_query', source_ip, query_data)
                
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"MongoDB query parsing error: {str(e)}")
    
    def _log_generic_query(self, query: str, source_ip: str):
        """Log generic database query"""
        query_data = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'database_type': 'generic',
            'query': query,
            'attack_type': 'database_query'
        }
        
        self.queries_executed.append(query_data)
        
        if self.logger:
            self.logger.log_attack('database_query', source_ip, query_data)
    
    def _log_auth_attempt(self, username: str, password: str, source_ip: str, db_type: str):
        """Log database authentication attempt"""
        auth_data = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'password': password,
            'source_ip': source_ip,
            'database_type': db_type,
            'attack_type': 'database_auth'
        }
        
        self.auth_attempts.append(auth_data)
        
        if self.logger:
            self.logger.log_authentication_attempt('database', source_ip, username, password, False)
        
        if self.monitoring:
            self.monitoring.log_database_attack('auth_attempt', source_ip, auth_data)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database honeypot statistics"""
        return {
            'total_connections': self.connection_count,
            'auth_attempts': len(self.auth_attempts),
            'queries_executed': len(self.queries_executed),
            'recent_auth_attempts': self.auth_attempts[-10:] if self.auth_attempts else [],
            'recent_queries': self.queries_executed[-10:] if self.queries_executed else [],
            'database_type': self.db_type,
            'running': self.running
        }
