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

**Status:** 🚧 In Development (MVP)

---

### 2. **SSL Certificate Checker** (`ssl-checker`)
Validate SSL/TLS certificates and identify potential issues.

**Features:**
- Certificate expiration warnings
- Chain validation
- Cipher suite analysis
- Multiple domains support
- Export reports

**Usage:**
```bash
ssl-checker --host example.com
ssl-checker --hosts-file domains.txt --warn-days 30
```

**Status:** 📋 Planned

---

### 3. **DNS Enumerator** (`dns-enum`)
Comprehensive DNS reconnaissance and health checking.

**Features:**
- Subdomain enumeration
- DNS record querying (A, AAAA, MX, TXT, etc.)
- Zone transfer testing
- DNS health checks
- Wildcard detection

**Usage:**
```bash
dns-enum --domain example.com
dns-enum --domain example.com --record-type MX
dns-enum --domain example.com --bruteforce --wordlist common.txt
```

**Status:** 📋 Planned

---

### 4. **IP Geolocation Tool** (`ip-geo`)
Lookup IP address information, geolocation, and ASN data.

**Features:**
- Geolocation data (country, city, coordinates)
- ASN and ISP information
- IP range analysis
- Bulk lookup support
- Offline database option

**Usage:**
```bash
ip-geo --ip 8.8.8.8
ip-geo --file ips.txt --output csv
```

**Status:** 📋 Planned

---

### 5. **Simple Firewall Manager** (`firewall-mgr`)
User-friendly wrapper for iptables/ufw with rule templates.

**Features:**
- Simplified rule syntax
- Common rule templates (web server, SSH hardening)
- Backup and restore
- Rule validation
- Dry-run mode

**Usage:**
```bash
firewall-mgr allow 80,443 --protocol tcp --comment "Web traffic"
firewall-mgr block 192.168.1.100 --reason "Suspicious activity"
firewall-mgr list --active
```

**Status:** 📋 Planned

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

- [x] Project setup and structure
- [ ] Port Scanner MVP (Phase 1)
- [ ] SSL Checker MVP (Phase 1)
- [ ] DNS Enumerator MVP (Phase 2)
- [ ] IP Geolocation MVP (Phase 2)
- [ ] Firewall Manager MVP (Phase 2)
- [ ] Integration testing suite
- [ ] CI/CD pipeline
- [ ] Published pip package
- [ ] Web dashboard (Phase 3)

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
