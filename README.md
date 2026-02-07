# 🔒 Security & Network Tools

> A collection of professional CLI tools for network analysis, security auditing, and infrastructure management.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## ⚠️ Legal Disclaimer

**These tools are intended for legitimate security testing and network administration purposes only.**

- ✅ Use on systems you own or have explicit permission to test
- ✅ Educational and professional security research
- ❌ **NEVER** use for unauthorized access or malicious purposes
- ❌ Scanning networks without permission may be illegal in your jurisdiction

**By using these tools, you accept full responsibility for your actions.**

---

## 🛠️ Available Tools

### 1. **Port Scanner** (`port-scanner`)
Fast, reliable TCP/UDP port scanner with service detection.

**Features:**
- TCP and UDP scanning
- Service version detection
- Parallel scanning with threading
- Multiple output formats (table, JSON, CSV)
- Rate limiting to avoid network congestion

**Usage:**
```bash
port-scanner --host example.com --ports 1-1000
port-scanner --host 192.168.1.1 --ports 80,443,8080 --timeout 2
port-scanner --host example.com --top-ports 100 --output json
```
<img width="783" height="298" alt="image" src="https://github.com/user-attachments/assets/2bceba5b-1b86-4e15-91bd-e8630301377d" />

**Status:** Complete

---

### 2. **SSL Certificate Checker** (`ssl-checker`)
Validate SSL/TLS certificates and identify potential issues.

**Features:**
- Certificate expiration warnings with configurable thresholds
- Chain validation and trust verification
- Subject Alternative Names (SANs) extraction
- Self-signed certificate detection
- Multiple domains support (batch checking)
- Detailed certificate information (issuer, serial, signature algorithm)
- Multiple output formats (table, detailed, JSON)
- File input support (check from list)

**Usage:**
```bash
# Check single domain
ssl-checker --host example.com

# Check multiple domains
ssl-checker --host google.com --host github.com

# Check from file
ssl-checker --file domains.txt --warn-days 30

# Detailed output
ssl-checker --host example.com --output detailed

# JSON output
ssl-checker --host example.com --output json
```
<img width="914" height="219" alt="image" src="https://github.com/user-attachments/assets/81e8d848-b0a4-4841-a76d-c8c1b9d50d23" />
<img width="711" height="516" alt="image" src="https://github.com/user-attachments/assets/afdae72f-fdaf-4baa-b0aa-b585e4e0ccf5" />

**Status:** Complete

---

### 3. **DNS Enumerator** (`dns-enum`)
Comprehensive DNS reconnaissance and health checking.

**Features:**
- DNS record querying (A, AAAA, MX, TXT, NS, SOA, CNAME)
- Multiple record type support
- Subdomain enumeration with wordlists
- Clean, structured output with Rich tables
- Error handling for invalid domains
- Timeout configuration

**Usage:**
```bash
# Query all common DNS records
dns-enum --domain example.com

# Query specific record type
dns-enum --domain example.com --record-type MX

# Enumerate subdomains
dns-enum --domain example.com --wordlist subdomains.txt

# Custom timeout
dns-enum --domain example.com --timeout 5
```

**Status:** ✅ Complete

---

### 4. **IP Geolocation Tool** (`ip-geo`)
Lookup IP address information, geolocation, and ASN data.

**Features:**
- Geolocation data (country, region, city, coordinates)
- ASN and organization information
- Timezone and currency data
- ISP detection
- Bulk lookup support from file
- Multiple output formats (table, JSON, CSV)
- Uses ipapi.co free API

**Usage:**
```bash
# Lookup single IP
ip-geo --ip 8.8.8.8

# Lookup multiple IPs from file
ip-geo --file ips.txt

# JSON output
ip-geo --ip 1.1.1.1 --output json

# CSV export
ip-geo --file ips.txt --output csv > results.csv
```

**Status:** ✅ Complete

---

### 5. **Firewall Manager** (`firewall-mgr`)
User-friendly wrapper for iptables/ufw with rule templates.

**Features:**
- Support for iptables and ufw backends
- Add/delete firewall rules with flexible options
- Enable/disable firewall
- List all active rules
- Reset firewall to defaults
- Backup/restore rules (iptables fully supported)
- Predefined templates (SSH, web, database)
- Source/destination IP filtering
- Port-based rules (TCP/UDP/ICMP)
- Traffic direction control (in/out)
- **Requires root/sudo privileges**

**Usage:**
```bash
# Check status
sudo firewall-mgr status

# Add rules
sudo firewall-mgr add --action allow --port 22 --protocol tcp
sudo firewall-mgr add --action allow --port 80 --comment "HTTP"

# Apply template
sudo firewall-mgr template web  # Allows HTTP/HTTPS

# List rules
sudo firewall-mgr list

# Backup rules
sudo firewall-mgr backup /backups/firewall.json

# Reset firewall
sudo firewall-mgr reset
```

**Status:** ✅ Complete

---

## 🚀 Installation

### Prerequisites
- Python 3.9 or higher
- pip
- (Optional) Virtual environment tool

### Install from source

```bash
# Clone the repository
git clone https://github.com/Shevanio/security-network-tools.git
cd security-network-tools

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

### Install via pip (future)

```bash
pip install security-network-tools
```

---

## 📖 Documentation

Detailed documentation for each tool is available in the [`docs/`](docs/) directory:

- [Port Scanner Guide](docs/port-scanner.md)
- [SSL Checker Guide](docs/ssl-checker.md)
- [DNS Enumerator Guide](docs/dns-enumerator.md)
- [IP Geolocation Guide](docs/ip-geolocator.md)
- [Firewall Manager Guide](docs/firewall-manager.md)

---

## 🧪 Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=tools --cov-report=html

# Run specific tool tests
pytest tests/test_port_scanner.py
```

### Code Quality

```bash
# Format code
black .

# Lint
ruff check .

# Type checking
mypy tools/
```

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Quick Start for Contributors

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests
5. Run quality checks (`black .`, `pytest`, `ruff check .`)
6. Commit (`git commit -m 'Add amazing feature'`)
7. Push (`git push origin feature/amazing-feature`)
8. Open a Pull Request

---

## 📊 Project Roadmap

- [x] Project setup and structure ✅
- [x] Port Scanner MVP ✅
- [x] SSL Checker MVP ✅
- [x] DNS Enumerator MVP ✅
- [x] IP Geolocation MVP ✅
- [x] Firewall Manager MVP ✅
- [ ] Integration testing suite
- [ ] Published pip package
- [ ] Web dashboard (Phase 3)

**🎉 All 5 core tools complete! (100%)**

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Inspired by industry-standard tools like nmap, masscan, and testssl.sh
- Built with modern Python best practices
- Community feedback and contributions

---

## 📧 Contact

For questions, issues, or suggestions:
- Open an issue on GitHub
- Reach out via discussions

**Remember: Use responsibly. Ethical hacking only.** 🛡️
