#!/usr/bin/env python3
"""
Honeypot Dashboard
Web-based dashboard for monitoring honeypot activities and statistics
"""

import os
import json
import time
import threading
from datetime import datetime, timedelta
from flask import Flask, render_template_string, request, jsonify, redirect, url_for, session
from werkzeug.security import check_password_hash, generate_password_hash
import glob

app = Flask(__name__)
app.secret_key = 'honeypot_dashboard_secret_key_2024'

class HoneypotDashboard:
    """Dashboard for honeypot monitoring and management"""
    
    def __init__(self):
        self.config = self.load_config()
        self.stats = {
            'total_attacks': 0,
            'web_attacks': 0,
            'ssh_attacks': 0,
            'database_attacks': 0,
            'unique_ips': set(),
            'recent_attacks': [],
            'attack_timeline': []
        }
        
        # Load existing attack data
        self.load_attack_data()
        
        # Start stats update thread
        self.stats_thread = threading.Thread(target=self.update_stats, daemon=True)
        self.stats_thread.start()
    
    def load_config(self):
        """Load configuration from config.json"""
        try:
            with open('config.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def load_attack_data(self):
        """Load attack data from log files"""
        try:
            # Load attack logs
            attack_files = glob.glob('logs/attacks/*.json')
            for file_path in attack_files:
                try:
                    with open(file_path, 'r') as f:
                        attack_data = json.load(f)
                        self.stats['recent_attacks'].append(attack_data)
                        self.stats['unique_ips'].add(attack_data.get('source_ip', 'unknown'))
                        
                        # Categorize attacks
                        service = attack_data.get('service', 'unknown')
                        if service == 'web':
                            self.stats['web_attacks'] += 1
                        elif service == 'ssh':
                            self.stats['ssh_attacks'] += 1
                        elif service == 'database':
                            self.stats['database_attacks'] += 1
                        
                except Exception as e:
                    print(f"Error loading attack file {file_path}: {e}")
            
            self.stats['total_attacks'] = len(self.stats['recent_attacks'])
            
        except Exception as e:
            print(f"Error loading attack data: {e}")
    
    def update_stats(self):
        """Update statistics periodically"""
        while True:
            try:
                # Reload attack data
                self.load_attack_data()
                
                # Update attack timeline
                self.update_attack_timeline()
                
                time.sleep(30)  # Update every 30 seconds
                
            except Exception as e:
                print(f"Stats update error: {e}")
                time.sleep(30)
    
    def update_attack_timeline(self):
        """Update attack timeline for charts"""
        try:
            # Group attacks by hour for the last 24 hours
            now = datetime.now()
            timeline = {}
            
            for i in range(24):
                hour = now - timedelta(hours=i)
                hour_key = hour.strftime('%Y-%m-%d %H:00')
                timeline[hour_key] = 0
            
            # Count attacks per hour
            for attack in self.stats['recent_attacks']:
                try:
                    attack_time = datetime.fromisoformat(attack['timestamp'])
                    hour_key = attack_time.strftime('%Y-%m-%d %H:00')
                    if hour_key in timeline:
                        timeline[hour_key] += 1
                except:
                    pass
            
            # Convert to list for chart
            self.stats['attack_timeline'] = [
                {'time': time, 'count': count} 
                for time, count in sorted(timeline.items())
            ]
            
        except Exception as e:
            print(f"Timeline update error: {e}")

# Initialize dashboard
dashboard = HoneypotDashboard()

# Authentication
def login_required(f):
    """Decorator for login required routes"""
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check credentials
        config = dashboard.load_config()
        dashboard_config = config.get('dashboard', {})
        
        if (username == dashboard_config.get('username', 'admin') and 
            password == dashboard_config.get('password', 'honeypot123')):
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template_string(login_template, error='Invalid credentials')
    
    return render_template_string(login_template)

@app.route('/logout')
def logout():
    """Logout"""
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Main dashboard page"""
    return render_template_string(dashboard_template, stats=dashboard.stats)

@app.route('/api/stats')
@login_required
def api_stats():
    """API endpoint for statistics"""
    return jsonify(dashboard.stats)

@app.route('/api/attacks')
@login_required
def api_attacks():
    """API endpoint for recent attacks"""
    recent_attacks = dashboard.stats['recent_attacks'][-50:]  # Last 50 attacks
    return jsonify(recent_attacks)

@app.route('/attacks')
@login_required
def attacks():
    """Attacks page"""
    return render_template_string(attacks_template, attacks=dashboard.stats['recent_attacks'])

@app.route('/config')
@login_required
def config_page():
    """Configuration page"""
    return render_template_string(config_template, config=dashboard.config)

# HTML Templates
login_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Dashboard - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 0; }
        .login-container { max-width: 400px; margin: 100px auto; background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .login-header { text-align: center; margin-bottom: 30px; }
        .login-header h1 { color: #333; margin: 0; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; color: #555; }
        .form-group input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 3px; box-sizing: border-box; }
        .btn { width: 100%; padding: 12px; background: #007cba; color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 16px; }
        .btn:hover { background: #005a87; }
        .error { color: red; margin-top: 10px; text-align: center; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🐝 Honeypot Dashboard</h1>
            <p>Please login to access the dashboard</p>
        </div>
        <form method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn">Login</button>
            {% if error %}
            <div class="error">{{ error }}</div>
            {% endif %}
        </form>
    </div>
</body>
</html>
"""

dashboard_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f0f0f0; }
        .header { background: #333; color: white; padding: 20px; }
        .header h1 { margin: 0; }
        .nav { background: #444; padding: 10px; }
        .nav a { color: white; text-decoration: none; margin-right: 20px; padding: 10px; }
        .nav a:hover { background: #555; }
        .container { max-width: 1200px; margin: 20px auto; padding: 0 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .stat-card h3 { margin: 0 0 10px 0; color: #333; }
        .stat-number { font-size: 2em; font-weight: bold; color: #007cba; }
        .chart-container { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .attack-list { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .attack-item { border-bottom: 1px solid #eee; padding: 10px 0; }
        .attack-item:last-child { border-bottom: none; }
        .attack-time { color: #666; font-size: 0.9em; }
        .attack-ip { font-weight: bold; color: #d73502; }
        .attack-type { color: #007cba; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🐝 Honeypot Dashboard</h1>
    </div>
    <div class="nav">
        <a href="/">Dashboard</a>
        <a href="/attacks">Attacks</a>
        <a href="/config">Configuration</a>
        <a href="/logout">Logout</a>
    </div>
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Attacks</h3>
                <div class="stat-number">{{ stats.total_attacks }}</div>
            </div>
            <div class="stat-card">
                <h3>Web Attacks</h3>
                <div class="stat-number">{{ stats.web_attacks }}</div>
            </div>
            <div class="stat-card">
                <h3>SSH Attacks</h3>
                <div class="stat-number">{{ stats.ssh_attacks }}</div>
            </div>
            <div class="stat-card">
                <h3>Database Attacks</h3>
                <div class="stat-number">{{ stats.database_attacks }}</div>
            </div>
            <div class="stat-card">
                <h3>Unique IPs</h3>
                <div class="stat-number">{{ stats.unique_ips|length }}</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h3>Attack Timeline (Last 24 Hours)</h3>
            <div id="timeline-chart" style="height: 300px; background: #f9f9f9; border: 1px solid #ddd; padding: 20px;">
                <p>Attack timeline chart would be displayed here</p>
            </div>
        </div>
        
        <div class="attack-list">
            <h3>Recent Attacks</h3>
            {% for attack in stats.recent_attacks[-10:] %}
            <div class="attack-item">
                <div class="attack-time">{{ attack.timestamp }}</div>
                <div class="attack-ip">{{ attack.source_ip }}</div>
                <div class="attack-type">{{ attack.service }} - {{ attack.attack_type }}</div>
            </div>
            {% endfor %}
        </div>
    </div>
    
    <script>
        // Auto-refresh stats every 30 seconds
        setInterval(function() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    // Update stats display
                    document.querySelector('.stat-card:nth-child(1) .stat-number').textContent = data.total_attacks;
                    document.querySelector('.stat-card:nth-child(2) .stat-number').textContent = data.web_attacks;
                    document.querySelector('.stat-card:nth-child(3) .stat-number').textContent = data.ssh_attacks;
                    document.querySelector('.stat-card:nth-child(4) .stat-number').textContent = data.database_attacks;
                    document.querySelector('.stat-card:nth-child(5) .stat-number').textContent = data.unique_ips.length;
                });
        }, 30000);
    </script>
</body>
</html>
"""

attacks_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Dashboard - Attacks</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f0f0f0; }
        .header { background: #333; color: white; padding: 20px; }
        .header h1 { margin: 0; }
        .nav { background: #444; padding: 10px; }
        .nav a { color: white; text-decoration: none; margin-right: 20px; padding: 10px; }
        .nav a:hover { background: #555; }
        .container { max-width: 1200px; margin: 20px auto; padding: 0 20px; }
        .attacks-table { background: white; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); overflow: hidden; }
        .attacks-table table { width: 100%; border-collapse: collapse; }
        .attacks-table th, .attacks-table td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        .attacks-table th { background: #f5f5f5; font-weight: bold; }
        .attacks-table tr:hover { background: #f9f9f9; }
        .attack-ip { font-weight: bold; color: #d73502; }
        .attack-type { color: #007cba; }
        .attack-time { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🐝 Honeypot Dashboard - Attacks</h1>
    </div>
    <div class="nav">
        <a href="/">Dashboard</a>
        <a href="/attacks">Attacks</a>
        <a href="/config">Configuration</a>
        <a href="/logout">Logout</a>
    </div>
    <div class="container">
        <div class="attacks-table">
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Source IP</th>
                        <th>Service</th>
                        <th>Attack Type</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {% for attack in attacks %}
                    <tr>
                        <td class="attack-time">{{ attack.timestamp }}</td>
                        <td class="attack-ip">{{ attack.source_ip }}</td>
                        <td>{{ attack.service }}</td>
                        <td class="attack-type">{{ attack.attack_type }}</td>
                        <td>{{ attack.details|tojson }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""

config_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Dashboard - Configuration</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f0f0f0; }
        .header { background: #333; color: white; padding: 20px; }
        .header h1 { margin: 0; }
        .nav { background: #444; padding: 10px; }
        .nav a { color: white; text-decoration: none; margin-right: 20px; padding: 10px; }
        .nav a:hover { background: #555; }
        .container { max-width: 1200px; margin: 20px auto; padding: 0 20px; }
        .config-section { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .config-section h3 { margin-top: 0; color: #333; }
        .config-item { margin-bottom: 15px; }
        .config-item label { display: block; margin-bottom: 5px; font-weight: bold; }
        .config-item input, .config-item select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 3px; box-sizing: border-box; }
        .config-item textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 3px; box-sizing: border-box; height: 100px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🐝 Honeypot Dashboard - Configuration</h1>
    </div>
    <div class="nav">
        <a href="/">Dashboard</a>
        <a href="/attacks">Attacks</a>
        <a href="/config">Configuration</a>
        <a href="/logout">Logout</a>
    </div>
    <div class="container">
        <div class="config-section">
            <h3>Honeypot Services</h3>
            <div class="config-item">
                <label>Web Service:</label>
                <input type="text" value="{{ config.services.web.host }}:{{ config.services.web.port }}" readonly>
            </div>
            <div class="config-item">
                <label>SSH Service:</label>
                <input type="text" value="{{ config.services.ssh.host }}:{{ config.services.ssh.port }}" readonly>
            </div>
            <div class="config-item">
                <label>Database Service:</label>
                <input type="text" value="{{ config.services.database.host }}:{{ config.services.database.port }}" readonly>
            </div>
        </div>
        
        <div class="config-section">
            <h3>Security Settings</h3>
            <div class="config-item">
                <label>Isolation Enabled:</label>
                <input type="text" value="{{ config.isolation.enabled }}" readonly>
            </div>
            <div class="config-item">
                <label>Outbound Restrictions:</label>
                <input type="text" value="{{ config.isolation.restrict_outbound }}" readonly>
            </div>
        </div>
        
        <div class="config-section">
            <h3>Monitoring</h3>
            <div class="config-item">
                <label>Packet Capture:</label>
                <input type="text" value="{{ config.monitoring.packet_capture }}" readonly>
            </div>
            <div class="config-item">
                <label>File Integrity:</label>
                <input type="text" value="{{ config.monitoring.file_integrity }}" readonly>
            </div>
        </div>
    </div>
</body>
</html>
"""

if __name__ == '__main__':
    # Load dashboard configuration
    config = dashboard.load_config()
    dashboard_config = config.get('dashboard', {})
    
    # Start dashboard server
    app.run(
        host=dashboard_config.get('host', '127.0.0.1'),
        port=dashboard_config.get('port', 9090),
        debug=False
    )
