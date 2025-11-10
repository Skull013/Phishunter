# 🎣 PhishHunter: Advanced Phishing Detection Tool

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)

A powerful command-line tool for detecting phishing URLs using multiple detection techniques and OSINT (Open Source Intelligence) integration.

## 🌟 Features

### Standard Security Checks
- ✅ **Suspicious Pattern Detection** - Identifies phishing indicators in URLs
- 🔒 **SSL Certificate Validation** - Checks certificate validity and expiration
- 📅 **Domain Age Analysis** - Detects newly registered domains
- 🌐 **DNS Record Investigation** - Analyzes DNS configurations
- ⚠️ **Reputation Scoring** - Risk assessment based on multiple factors

### OSINT Intelligence Integration
- 🦠 **VirusTotal** - Checks against 70+ antivirus engines
- 🔍 **Shodan** - Discovers open ports and vulnerabilities
- 💔 **HaveIBeenPwned** - Identifies data breach involvement
- 📸 **URLScan.io** - Live URL scanning and screenshot capture
- 👽 **AlienVault OTX** - Threat intelligence from global community

### Advanced Detection
- 🎯 Typosquatting detection (googIe.com, paypaI.com)
- 🔗 URL shortener identification
- 📏 Suspicious URL length analysis
- 🔐 Certificate domain matching
- ⚙️ Non-standard port detection
- 🎭 Multiple keyword pattern matching

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/PhishHunter.git
cd PhishHunter
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

## 🔑 API Keys Setup (Optional but Recommended)

Get free API keys from these services:

1. **VirusTotal**: https://www.virustotal.com/gui/sign-in
2. **Shodan**: https://account.shodan.io/
3. **HaveIBeenPwned**: https://haveibeenpwned.com/API/Key
4. **URLScan.io**: https://urlscan.io/user/signup
5. **AlienVault OTX**: https://otx.alienvault.com/ (free)

### Set Environment Variables (Optional)
```bash
# Linux/Mac
export VT_API_KEY="your_virustotal_key"
export SHODAN_API_KEY="your_shodan_key"
export HIBP_API_KEY="your_hibp_key"
export URLSCAN_API_KEY="your_urlscan_key"
export ALIENVAULT_API_KEY="your_alienvault_key"

# Windows (PowerShell)
$env:VT_API_KEY="your_virustotal_key"
```

## 📖 Usage

### Basic Usage (No API Keys Required)
```bash
# Analyze a single URL
python phishhunter.py -u https://suspicious-site.com

# Without OSINT checks
python phishhunter.py -u https://example.com --no-osint
```

### With OSINT Integration
```bash
# Single URL with all OSINT checks
python phishhunter.py -u https://suspicious-site.com \
    --vt YOUR_VT_KEY \
    --shodan YOUR_SHODAN_KEY \
    --hibp YOUR_HIBP_KEY \
    --urlscan YOUR_URLSCAN_KEY \
    --alienvault YOUR_ALIENVAULT_KEY
```

### Batch Scanning
```bash
# Create urls.txt with one URL per line
# Then run:
python phishhunter.py -b urls.txt

# With JSON output
python phishhunter.py -b urls.txt --vt YOUR_VT_KEY -j results.json
```

### Save Results
```bash
# Save detailed results to JSON
python phishhunter.py -u https://example.com -j report.json
```

## 📊 Example Output

```
============================================================
PhishHunter OSINT Analysis Report
============================================================
Analyzing: https://suspicious-site.com
Domain: suspicious-site.com

[*] Checking suspicious patterns...
[*] Checking SSL certificate...
[*] Checking domain age...
[*] Checking DNS records...
[*] Checking reputation...

============================================================
OSINT Intelligence Gathering
============================================================
[OSINT] VirusTotal scan...
[OSINT] Shodan lookup...

============================================================
Analysis Results
============================================================
Risk Score: 85/100
Risk Level: ⚠️ HIGH

STANDARD SECURITY CHECKS
------------------------------------------------------------
▶ SUSPICIOUS PATTERNS
  ⚠ Uses IP address instead of domain
  ⚠ Contains suspicious keyword: login

▶ SSL
  valid: False
  error: [SSL: CERTIFICATE_VERIFY_FAILED]

▶ DOMAIN AGE
  ⚠ Warning: Very new domain (< 30 days)
  age_days: 15

OSINT INTELLIGENCE
------------------------------------------------------------
▶ VIRUSTOTAL
  malicious: 12
  detection_rate: 12/70
  ⚠ Detected as malicious by 12 engines

============================================================
RECOMMENDATION
============================================================
⚠️  HIGH RISK - This URL shows multiple signs of phishing.
   DO NOT proceed with this website.
   Do not enter any credentials or personal information.
============================================================
```

## 🎯 Risk Score Interpretation

| Score | Level | Description |
|-------|-------|-------------|
| 0-39 | 🟢 LOW | URL appears relatively safe |
| 40-69 | 🟡 MEDIUM | Exercise caution |
| 70-100 | 🔴 HIGH | Strong phishing indicators - DO NOT PROCEED |

## 📁 Project Structure

```
PhishHunter/
├── phishhunter.py          # Main application
├── requirements.txt         # Python dependencies
├── README.md               # Documentation
├── urls.txt                # Sample URLs for testing
└── LICENSE                 # MIT License
```

## 🛡️ Detection Capabilities

### Pattern Analysis
- IP-based URLs
- Excessive subdomains (>3)
- Suspicious keywords (login, verify, secure, etc.)
- URL shorteners
- Authentication spoofing (@symbol)
- Typosquatting attempts
- Long URLs (>75 characters)

### Domain Intelligence
- Domain registration age
- WHOIS information
- Registrar details
- Domain status

### SSL/TLS Analysis
- Certificate validity
- Expiration dates
- Domain matching
- Issuer information

### DNS Investigation
- A records
- MX records (mail servers)
- TXT records (SPF, DKIM)
- NS records (nameservers)

## ⚠️ Disclaimer

This tool is for educational and security research purposes only. Users are responsible for ensuring they have proper authorization before scanning domains they do not own.

## 🙏 Acknowledgments

- **VirusTotal** for malware detection database
- **Shodan** for internet-wide port scanning
- **HaveIBeenPwned** for breach data
- **URLScan.io** for URL analysis
- **AlienVault OTX** for threat intelligence

## 📧 Contact

- GitHub: [@Skull013](https://github.com/Skull013)
- Project Link: [https://github.com/Skull013/PhishHunter](https://github.com/Skull013/PhishHunter)

## 🔮 Future Enhancements

- [ ] Machine Learning integration
- [ ] GUI interface
- [ ] Real-time monitoring
- [ ] Email notification system
- [ ] Browser extension
- [ ] API endpoint

---

**Made with ❤️ for Cybersecurity**
