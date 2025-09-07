"""
Web Honeypot Module
Simulates a vulnerable web server to attract and log web-based attacks
"""

import os
import json
import time
import threading
from flask import Flask, request, render_template_string, jsonify, redirect, url_for
from datetime import datetime
from typing import Dict, Any, Optional

class WebHoneypot:
    """
    Web Honeypot - Simulates vulnerable web services
    Includes fake admin panels, login forms, and vulnerable endpoints
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, 
                 logger=None, monitoring=None):
        """Initialize the web honeypot"""
        self.host = host
        self.port = port
        self.logger = logger
        self.monitoring = monitoring
        self.app = Flask(__name__)
        self.server_thread = None
        self.running = False
        
        # Setup routes
        self.setup_routes()
        
        # Attack tracking
        self.attack_count = 0
        self.login_attempts = []
        
    def setup_routes(self):
        """Setup all web honeypot routes"""
        
        @self.app.route('/')
        def index():
            """Main page - looks like a legitimate website"""
            return render_template_string(self.get_main_page_template())
        
        @self.app.route('/admin')
        def admin_panel():
            """Fake admin panel - main target for attacks"""
            return render_template_string(self.get_admin_panel_template())
        
        @self.app.route('/admin/login', methods=['GET', 'POST'])
        def admin_login():
            """Fake admin login - logs all login attempts"""
            if request.method == 'POST':
                username = request.form.get('username', '')
                password = request.form.get('password', '')
                source_ip = request.remote_addr
                
                # Log the login attempt
                self.log_login_attempt(username, password, source_ip)
                
                # Always show "invalid credentials" to keep them trying
                return render_template_string(self.get_login_failed_template())
            
            return render_template_string(self.get_login_template())
        
        @self.app.route('/wp-admin')
        def wordpress_admin():
            """Fake WordPress admin - common target"""
            return render_template_string(self.get_wordpress_admin_template())
        
        @self.app.route('/phpmyadmin')
        def phpmyadmin():
            """Fake phpMyAdmin - database admin tool"""
            return render_template_string(self.get_phpmyadmin_template())
        
        @self.app.route('/config.php')
        def config_file():
            """Fake config file - often targeted for sensitive info"""
            self.log_file_access_attempt(request.remote_addr, '/config.php')
            return "<?php\n// Configuration file\n$db_host = 'localhost';\n$db_user = 'admin';\n$db_pass = 'password123';\n?>"
        
        @self.app.route('/.env')
        def env_file():
            """Fake environment file - contains sensitive data"""
            self.log_file_access_attempt(request.remote_addr, '/.env')
            return "DB_HOST=localhost\nDB_USER=admin\nDB_PASSWORD=secret123\nAPI_KEY=abc123def456"
        
        @self.app.route('/robots.txt')
        def robots_txt():
            """Fake robots.txt - reveals hidden directories"""
            return "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /config/\nDisallow: /logs/"
        
        @self.app.route('/backup/')
        def backup_directory():
            """Fake backup directory"""
            self.log_directory_access_attempt(request.remote_addr, '/backup/')
            return "Directory listing denied"
        
        @self.app.route('/api/users')
        def api_users():
            """Fake API endpoint"""
            self.log_api_access_attempt(request.remote_addr, '/api/users')
            return jsonify({"error": "Unauthorized access"})
        
        @self.app.route('/<path:path>')
        def catch_all(path):
            """Catch all other requests"""
            self.log_404_attempt(request.remote_addr, f'/{path}')
            return "404 - Page not found", 404
    
    def get_main_page_template(self):
        """Get main page HTML template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Welcome to Our Website</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background: #333; color: white; padding: 20px; }
                .content { margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Welcome to Our Company Website</h1>
            </div>
            <div class="content">
                <p>We provide excellent services to our customers.</p>
                <p>For administrative access, please contact the system administrator.</p>
            </div>
        </body>
        </html>
        """
    
    def get_admin_panel_template(self):
        """Get admin panel HTML template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Panel</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
                .login-form { background: white; padding: 30px; border-radius: 5px; width: 300px; margin: 100px auto; }
                input { width: 100%; padding: 10px; margin: 10px 0; }
                button { background: #007cba; color: white; padding: 10px 20px; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="login-form">
                <h2>Admin Login</h2>
                <form method="POST" action="/admin/login">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
            </div>
        </body>
        </html>
        """
    
    def get_login_template(self):
        """Get login form template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
                .login-form { background: white; padding: 30px; border-radius: 5px; width: 300px; margin: 100px auto; }
                input { width: 100%; padding: 10px; margin: 10px 0; }
                button { background: #007cba; color: white; padding: 10px 20px; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="login-form">
                <h2>Please Login</h2>
                <form method="POST">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
            </div>
        </body>
        </html>
        """
    
    def get_login_failed_template(self):
        """Get login failed template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Failed</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
                .login-form { background: white; padding: 30px; border-radius: 5px; width: 300px; margin: 100px auto; }
                .error { color: red; margin: 10px 0; }
                input { width: 100%; padding: 10px; margin: 10px 0; }
                button { background: #007cba; color: white; padding: 10px 20px; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="login-form">
                <h2>Login Failed</h2>
                <div class="error">Invalid username or password. Please try again.</div>
                <form method="POST">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
            </div>
        </body>
        </html>
        """
    
    def get_wordpress_admin_template(self):
        """Get WordPress admin template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>WordPress Admin</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
                .wp-admin { background: white; padding: 30px; border-radius: 5px; width: 400px; margin: 100px auto; }
                input { width: 100%; padding: 10px; margin: 10px 0; }
                button { background: #0073aa; color: white; padding: 10px 20px; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="wp-admin">
                <h2>WordPress Admin Login</h2>
                <form method="POST" action="/wp-admin/login">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
            </div>
        </body>
        </html>
        """
    
    def get_phpmyadmin_template(self):
        """Get phpMyAdmin template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>phpMyAdmin</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
                .phpmyadmin { background: white; padding: 30px; border-radius: 5px; width: 400px; margin: 100px auto; }
                input { width: 100%; padding: 10px; margin: 10px 0; }
                button { background: #d73502; color: white; padding: 10px 20px; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="phpmyadmin">
                <h2>phpMyAdmin Login</h2>
                <form method="POST" action="/phpmyadmin/login">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
            </div>
        </body>
        </html>
        """
    
    def log_login_attempt(self, username: str, password: str, source_ip: str):
        """Log login attempt"""
        self.attack_count += 1
        login_data = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'password': password,
            'source_ip': source_ip,
            'user_agent': request.headers.get('User-Agent', ''),
            'attack_type': 'web_login_attempt'
        }
        
        self.login_attempts.append(login_data)
        
        if self.logger:
            self.logger.log_authentication_attempt('web', source_ip, username, password, False)
        
        if self.monitoring:
            self.monitoring.log_web_attack('login_attempt', source_ip, login_data)
    
    def log_file_access_attempt(self, source_ip: str, file_path: str):
        """Log file access attempt"""
        if self.logger:
            self.logger.log_attack('file_access', source_ip, {
                'file_path': file_path,
                'user_agent': request.headers.get('User-Agent', ''),
                'attack_type': 'sensitive_file_access'
            })
    
    def log_directory_access_attempt(self, source_ip: str, directory: str):
        """Log directory access attempt"""
        if self.logger:
            self.logger.log_attack('directory_access', source_ip, {
                'directory': directory,
                'user_agent': request.headers.get('User-Agent', ''),
                'attack_type': 'directory_enumeration'
            })
    
    def log_api_access_attempt(self, source_ip: str, endpoint: str):
        """Log API access attempt"""
        if self.logger:
            self.logger.log_attack('api_access', source_ip, {
                'endpoint': endpoint,
                'user_agent': request.headers.get('User-Agent', ''),
                'attack_type': 'api_enumeration'
            })
    
    def log_404_attempt(self, source_ip: str, path: str):
        """Log 404 attempts (potential scanning)"""
        if self.logger:
            self.logger.log_attack('404_scanning', source_ip, {
                'requested_path': path,
                'user_agent': request.headers.get('User-Agent', ''),
                'attack_type': 'path_enumeration'
            })
    
    def start(self):
        """Start the web honeypot server"""
        if not self.running:
            self.running = True
            self.server_thread = threading.Thread(
                target=self._run_server,
                daemon=True
            )
            self.server_thread.start()
    
    def stop(self):
        """Stop the web honeypot server"""
        self.running = False
        if self.server_thread:
            self.server_thread.join(timeout=5)
    
    def _run_server(self):
        """Run the Flask server"""
        try:
            self.app.run(
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False,
                threaded=True
            )
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"Web honeypot server error: {str(e)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get web honeypot statistics"""
        return {
            'total_attacks': self.attack_count,
            'login_attempts': len(self.login_attempts),
            'recent_attempts': self.login_attempts[-10:] if self.login_attempts else [],
            'running': self.running
        }
