"""
SSH Honeypot Module
Simulates a vulnerable SSH server to attract and log SSH-based attacks
"""

import os
import socket
import threading
import time
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
import paramiko
from paramiko import ServerInterface, SFTPServerInterface, SFTPHandle
from paramiko.common import AUTH_SUCCESSFUL, AUTH_FAILED, OPEN_SUCCEEDED

class SSHHoneypot(ServerInterface):
    """
    SSH Honeypot - Simulates vulnerable SSH server
    Logs all connection attempts, authentication attempts, and commands
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 2222, 
                 logger=None, monitoring=None):
        """Initialize the SSH honeypot"""
        self.host = host
        self.port = port
        self.logger = logger
        self.monitoring = monitoring
        self.server_socket = None
        self.running = False
        self.server_thread = None
        
        # Attack tracking
        self.connection_count = 0
        self.auth_attempts = []
        self.commands_executed = []
        
        # Fake system information
        self.fake_hostname = "server-01"
        self.fake_os = "Linux server-01 5.4.0-74-generic #83-Ubuntu SMP"
        
    def start(self):
        """Start the SSH honeypot server"""
        if not self.running:
            self.running = True
            self.server_thread = threading.Thread(
                target=self._run_server,
                daemon=True
            )
            self.server_thread.start()
    
    def stop(self):
        """Stop the SSH honeypot server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.server_thread:
            self.server_thread.join(timeout=5)
    
    def _run_server(self):
        """Run the SSH server"""
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            if self.logger:
                self.logger.log_system_event(f"SSH honeypot listening on {self.host}:{self.port}")
            
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
                            self.logger.log_error("SSH server socket error")
                    break
                    
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"SSH honeypot server error: {str(e)}")
    
    def _handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        """Handle individual SSH client connection"""
        source_ip = client_address[0]
        
        try:
            # Log connection attempt
            if self.logger:
                self.logger.log_connection('ssh', source_ip, self.port, {
                    'timestamp': datetime.now().isoformat(),
                    'client_address': client_address
                })
            
            # Create SSH transport
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self._generate_host_key())
            transport.set_subsystem_handler('sftp', paramiko.SFTPServer, SFTPServerInterface)
            
            # Start SSH server
            transport.start_server(server=self)
            
            # Wait for authentication
            channel = transport.accept(20)
            if channel is None:
                transport.close()
                return
            
            # Log successful connection
            if self.logger:
                self.logger.log_system_event(f"SSH connection established from {source_ip}")
            
            # Send welcome message
            channel.send(f"Welcome to {self.fake_hostname}\r\n")
            channel.send(f"{self.fake_os}\r\n")
            channel.send("Last login: " + datetime.now().strftime("%a %b %d %H:%M:%S %Y") + "\r\n")
            
            # Interactive shell simulation
            self._simulate_shell(channel, source_ip)
            
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"SSH client handling error: {str(e)}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _simulate_shell(self, channel, source_ip: str):
        """Simulate an interactive shell"""
        try:
            # Send prompt
            channel.send(f"root@{self.fake_hostname}:~# ")
            
            while True:
                # Wait for command
                if channel.recv_ready():
                    command = channel.recv(1024).decode('utf-8').strip()
                    
                    if not command:
                        break
                    
                    # Log command execution
                    self._log_command(source_ip, command)
                    
                    # Simulate command execution
                    response = self._execute_fake_command(command)
                    channel.send(response + "\r\n")
                    channel.send(f"root@{self.fake_hostname}:~# ")
                    
                time.sleep(0.1)
                
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"Shell simulation error: {str(e)}")
    
    def _log_command(self, source_ip: str, command: str):
        """Log command execution attempt"""
        command_data = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'command': command,
            'attack_type': 'ssh_command_execution'
        }
        
        self.commands_executed.append(command_data)
        
        if self.logger:
            self.logger.log_attack('ssh_command', source_ip, command_data)
        
        if self.monitoring:
            self.monitoring.log_ssh_attack('command_execution', source_ip, command_data)
    
    def _execute_fake_command(self, command: str) -> str:
        """Execute fake command and return response"""
        command_lower = command.lower().strip()
        
        # Common commands and their fake responses
        if command_lower in ['ls', 'dir']:
            return "total 8\ndrwxr-xr-x 2 root root 4096 Jan 15 10:30 .\ndrwxr-xr-x 3 root root 4096 Jan 15 10:30 ..\n-rw-r--r-- 1 root root  123 Jan 15 10:30 config.txt\n-rw-r--r-- 1 root root  456 Jan 15 10:30 data.db"
        
        elif command_lower in ['pwd']:
            return "/root"
        
        elif command_lower in ['whoami']:
            return "root"
        
        elif command_lower in ['id']:
            return "uid=0(root) gid=0(root) groups=0(root)"
        
        elif command_lower in ['uname', 'uname -a']:
            return self.fake_os
        
        elif command_lower in ['ps', 'ps aux']:
            return "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  77616  8584 ?        Ss   Jan15   0:01 /sbin/init\nroot         2  0.0  0.0      0     0 ?        S    Jan15   0:00 [kthreadd]"
        
        elif command_lower in ['netstat', 'netstat -tulpn']:
            return "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\ntcp        0      0 0.0.0.0:22             0.0.0.0:*               LISTEN      1234/sshd\ntcp        0      0 0.0.0.0:80             0.0.0.0:*               LISTEN      5678/apache2"
        
        elif command_lower in ['cat /etc/passwd']:
            return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin"
        
        elif command_lower in ['cat /etc/shadow']:
            return "root:$6$salt$hash:18000:0:99999:7:::\ndaemon:*:18000:0:99999:7:::\nbin:*:18000:0:99999:7:::"
        
        elif command_lower.startswith('wget') or command_lower.startswith('curl'):
            return "Connecting to remote server...\nDownload complete."
        
        elif command_lower.startswith('nc ') or command_lower.startswith('netcat '):
            return "Connection established to remote host"
        
        elif command_lower in ['exit', 'quit']:
            return "Goodbye!"
        
        else:
            return f"bash: {command}: command not found"
    
    def _generate_host_key(self):
        """Generate a fake host key for SSH"""
        # In a real implementation, you'd load an actual host key
        # For the honeypot, we'll create a temporary one
        from paramiko import RSAKey
        import io
        
        # Create a temporary RSA key
        key = RSAKey.generate(2048)
        return key
    
    # SSH Server Interface Methods
    def check_auth_password(self, username: str, password: str) -> int:
        """Handle password authentication attempts"""
        source_ip = getattr(self, '_current_client_ip', 'unknown')
        
        # Log authentication attempt
        auth_data = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'password': password,
            'source_ip': source_ip,
            'attack_type': 'ssh_password_auth'
        }
        
        self.auth_attempts.append(auth_data)
        
        if self.logger:
            self.logger.log_authentication_attempt('ssh', source_ip, username, password, False)
        
        if self.monitoring:
            self.monitoring.log_ssh_attack('auth_attempt', source_ip, auth_data)
        
        # Always fail authentication to keep them trying
        return AUTH_FAILED
    
    def check_auth_publickey(self, username: str, key) -> int:
        """Handle public key authentication attempts"""
        source_ip = getattr(self, '_current_client_ip', 'unknown')
        
        # Log public key attempt
        key_data = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'key_type': key.get_name(),
            'key_fingerprint': hashlib.md5(key.asbytes()).hexdigest(),
            'source_ip': source_ip,
            'attack_type': 'ssh_publickey_auth'
        }
        
        if self.logger:
            self.logger.log_attack('ssh_publickey', source_ip, key_data)
        
        # Always fail authentication
        return AUTH_FAILED
    
    def check_channel_request(self, kind: str, chanid: int) -> int:
        """Handle channel requests"""
        if kind == 'session':
            return OPEN_SUCCEEDED
        return OPEN_SUCCEEDED
    
    def get_allowed_auths(self, username: str) -> str:
        """Return allowed authentication methods"""
        return 'password,publickey'
    
    def get_banner(self) -> Tuple[str, str]:
        """Return SSH banner"""
        banner = f"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2"
        return banner, 'en'
    
    def get_stats(self) -> Dict[str, Any]:
        """Get SSH honeypot statistics"""
        return {
            'total_connections': self.connection_count,
            'auth_attempts': len(self.auth_attempts),
            'commands_executed': len(self.commands_executed),
            'recent_auth_attempts': self.auth_attempts[-10:] if self.auth_attempts else [],
            'recent_commands': self.commands_executed[-10:] if self.commands_executed else [],
            'running': self.running
        }
