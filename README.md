# 🐝 Honeypot System

A comprehensive cybersecurity honeypot implementation designed to attract, detect, and analyze unauthorized or malicious activity. This system acts as a decoy to trick attackers into interacting with it while logging their behavior for analysis.

## 🔍 What Is This Honeypot?

This honeypot system is a deliberately vulnerable system that:
- **Looks appealing to hackers** - Simulates real services with apparent vulnerabilities
- **Tricks them into interacting** - Provides fake login forms, admin panels, and services
- **Logs their behavior** - Records all interactions, attacks, and methods for analysis

## 🛠 Features

### Core Components
- **Web Honeypot** - Fake web server with vulnerable endpoints (port 8080)
- **SSH Honeypot** - Simulated SSH server for brute force detection (port 2222)
- **Database Honeypot** - Fake database server for SQL injection attempts (port 3306)
- **Monitoring System** - Comprehensive logging and analysis
- **Network Isolation** - Prevents honeypot from being used to attack other systems
- **Web Dashboard** - Real-time monitoring and statistics

### Security Features
- **Attack Detection** - Identifies brute force, scanning, and exploitation attempts
- **Behavioral Analysis** - Tracks attacker patterns and methods
- **Threat Intelligence** - Collects data on attack vectors and malware
- **Network Isolation** - Restricts outbound connections to prevent lateral movement
- **Comprehensive Logging** - Records all activities with timestamps and details

## 🚀 Quick Start

### Prerequisites
- Python 3.7 or higher
- Administrator/root privileges (for network isolation)
- Windows, Linux, or macOS

### Installation

1. **Clone or download the honeypot files**
   ```bash
   # Ensure you have all the files in your honeypot directory
   ```

2. **Install Python dependencies**
   
   **Option A: Automatic installation (recommended)**
   ```bash
   python install_dependencies.py
   ```
   
   **Option B: Manual installation**
   ```bash
   pip install -r requirements.txt
   ```
   
   **Note**: Some dependencies are optional:
   - `watchdog` - For advanced file monitoring (fallback available)
   - `scapy` - For advanced packet capture (basic monitoring available)

3. **Configure the honeypot**
   ```bash
   # Edit config.json to customize settings
   # Default configuration is provided
   ```

4. **Start the honeypot system**
   ```bash
   python start_honeypot.py
   # OR
   python honeypot.py
   ```

5. **Access the dashboard** (optional)
   ```bash
   python dashboard.py
   # Open browser to http://localhost:9090
   # Default login: admin / honeypot123
   ```

## 📋 Configuration

The `config.json` file contains all configuration options:

### Services Configuration
```json
{
  "services": {
    "web": {
      "enabled": true,
      "port": 8080,
      "host": "0.0.0.0"
    },
    "ssh": {
      "enabled": true,
      "port": 2222,
      "host": "0.0.0.0"
    },
    "database": {
      "enabled": true,
      "port": 3306,
      "host": "0.0.0.0",
      "db_type": "mysql"
    }
  }
}
```

### Security Settings
```json
{
  "isolation": {
    "enabled": true,
    "restrict_outbound": true,
    "allowed_ports": [80, 443, 53],
    "blocked_ports": [22, 23, 25, 53, 80, 443, 993, 995]
  }
}
```

## 🎯 Example Use Cases

### 1. Admin Login Portal
The honeypot includes a fake admin login portal at `http://localhost:8080/admin`. Any login attempts are logged with:
- Source IP address
- Username and password attempts
- Timestamp and user agent
- Attack type classification

### 2. SSH Brute Force Detection
The SSH honeypot on port 2222 logs all connection attempts and authentication failures, helping identify:
- Brute force attacks
- Common username/password combinations
- Attack patterns and timing

### 3. Database Attack Detection
The database honeypot simulates MySQL, PostgreSQL, and MongoDB servers to detect:
- SQL injection attempts
- Database enumeration
- Authentication attacks

## 📊 Monitoring and Analysis

### Dashboard Features
- **Real-time Statistics** - Total attacks, service breakdown, unique IPs
- **Attack Timeline** - Visual representation of attack patterns
- **Recent Attacks** - Detailed log of recent attack attempts
- **Configuration View** - Current honeypot settings

### Log Files
All activities are logged to the `logs/` directory:
- `logs/attacks/` - Individual attack logs in JSON format
- `logs/connections/` - Connection attempt logs
- `logs/auth/` - Authentication attempt logs
- `honeypot.log` - Main system log

### Attack Data Collected
- **Source IP addresses** and geolocation
- **Attack vectors** and methods used
- **Malware signatures** and tools
- **Attacker behavior patterns**
- **Timing and frequency** of attacks

## ⚠️ Security Considerations

### Network Isolation
The honeypot includes network isolation features to prevent it from being used to attack other systems:
- **Outbound connection restrictions** - Blocks access to internal networks
- **Firewall rules** - Prevents lateral movement
- **Process monitoring** - Detects suspicious activities

### Legal and Ethical Considerations
- **Consent** - Ensure you have permission to deploy honeypots
- **Data privacy** - Handle logged data according to local laws
- **Responsible disclosure** - Report findings appropriately

### Best Practices
- **Isolate the honeypot** from production networks
- **Monitor regularly** for new attack patterns
- **Update signatures** and detection rules
- **Backup logs** for analysis and reporting

## 🔧 Advanced Configuration

### Custom Services
You can add custom honeypot services by extending the base classes:
```python
from modules.base_honeypot import BaseHoneypot

class CustomHoneypot(BaseHoneypot):
    def __init__(self, host, port, logger, monitoring):
        super().__init__(host, port, logger, monitoring)
        # Custom initialization
```

### Monitoring Integration
Integrate with external monitoring systems:
```python
# Send alerts to external systems
def send_alert(attack_data):
    # Custom alerting logic
    pass
```

## 📈 Performance and Scaling

### Resource Requirements
- **CPU**: Minimal (single core sufficient)
- **Memory**: 512MB - 1GB recommended
- **Storage**: 1GB+ for logs (depends on attack volume)
- **Network**: Low bandwidth usage

### Scaling Considerations
- **Multiple instances** - Deploy across different networks
- **Load balancing** - Distribute traffic across honeypots
- **Centralized logging** - Aggregate logs from multiple instances

## 🐛 Troubleshooting

### Common Issues

1. **Import errors or missing dependencies**
   - Run `python install_dependencies.py` to install all dependencies
   - For manual installation: `pip install -r requirements.txt`
   - Some packages are optional and have fallbacks (watchdog, scapy)

2. **Permission denied errors**
   - Ensure running with administrator/root privileges
   - Check firewall and antivirus settings

3. **Port conflicts**
   - Change ports in config.json if default ports are in use
   - Check for existing services on configured ports

4. **Network isolation not working**
   - Verify administrator privileges
   - Check if required tools (iptables, netsh) are available

5. **Dashboard not accessible**
   - Check if port 9090 is available
   - Verify firewall settings allow local connections

6. **File monitoring warnings**
   - If you see "watchdog not available" warnings, this is normal
   - File monitoring will use a fallback method
   - Install watchdog for better file monitoring: `pip install watchdog`

### Log Analysis
Check the main log file for errors:
```bash
tail -f logs/honeypot.log
```

## 📚 Additional Resources

### Honeypot Types
- **Low-Interaction**: Easy to deploy, limited data collection
- **High-Interaction**: Complex setup, detailed attack data
- **Production**: Deployed in real networks for protection
- **Research**: Used for studying attacker behavior

### Related Tools
- **Cowrie** - SSH honeypot
- **Dionaea** - Malware honeypot
- **Kippo** - SSH honeypot
- **Glastopf** - Web application honeypot

## 🤝 Contributing

This honeypot system is designed for educational and research purposes. Contributions and improvements are welcome:

1. **Report issues** - Help identify bugs and security problems
2. **Suggest features** - Propose new honeypot services or monitoring capabilities
3. **Improve documentation** - Help others understand and use the system
4. **Share findings** - Contribute to the cybersecurity community

## ⚖️ Legal Notice

This honeypot system is provided for educational and research purposes only. Users are responsible for:
- **Compliance with local laws** and regulations
- **Proper authorization** before deployment
- **Ethical use** of collected data
- **Responsible disclosure** of findings

## 📞 Support

For questions, issues, or contributions:
- **Documentation** - Check this README and code comments
- **Logs** - Review log files for error details
- **Configuration** - Verify config.json settings
- **Community** - Share experiences and solutions

---

**Remember**: Honeypots are powerful tools for cybersecurity research and threat detection. Use them responsibly and ethically to improve security for everyone.
