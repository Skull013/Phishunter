#!/usr/bin/env python3
"""
PhishHunter: Enhanced Phishing Detection with OSINT Integration
Author: Security Team
Version: 3.0
Features: VirusTotal, Shodan, HaveIBeenPwned, URLScan, Threat Intelligence
"""

import re
import socket
import ssl
import whois
import requests
from urllib.parse import urlparse
from datetime import datetime
import argparse
import json
from colorama import init, Fore, Style
import dns.resolver
import time
import os
import hashlib

# Initialize colorama
init(autoreset=True)

class PhishHunter:
    def __init__(self, url, api_keys=None):
        self.url = url
        self.domain = self.extract_domain(url)
        self.api_keys = api_keys or {}
        self.results = {
            'url': url,
            'domain': self.domain,
            'risk_score': 0,
            'checks': {},
            'osint': {},
            'timestamp': datetime.now().isoformat()
        }
        
    def extract_domain(self, url):
        """Extract domain from URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    
    def check_suspicious_patterns(self):
        """Check for suspicious URL patterns"""
        suspicious_score = 0
        flags = []
        
        # Check for IP address instead of domain
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self.domain):
            suspicious_score += 20
            flags.append("Uses IP address instead of domain")
        
        # Check for excessive subdomains
        subdomain_count = self.domain.count('.')
        if subdomain_count > 3:
            suspicious_score += 15
            flags.append(f"Excessive subdomains ({subdomain_count})")
        
        # Check for suspicious keywords
        phishing_keywords = ['login', 'secure', 'account', 'update', 'verify', 
                            'banking', 'paypal', 'amazon', 'microsoft', 'apple',
                            'signin', 'validation', 'suspended', 'locked']
        found_keywords = [kw for kw in phishing_keywords if kw in self.url.lower()]
        if found_keywords:
            suspicious_score += 10 * len(found_keywords)
            flags.append(f"Contains suspicious keywords: {', '.join(found_keywords)}")
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
        if any(self.domain == shortener or self.domain.endswith('.' + shortener) for shortener in shorteners):
            suspicious_score += 25
            flags.append("Uses URL shortener")
        
        # Check for @ symbol
        if '@' in self.url:
            suspicious_score += 30
            flags.append("Contains @ symbol (authentication spoofing)")
        
        # Check for excessive hyphens
        if self.domain.count('-') > 2:
            suspicious_score += 10
            flags.append("Excessive hyphens in domain")
        
        # Check for typosquatting
        typosquat_patterns = {
            'googIe': 'google', 'paypaI': 'paypal', 'arnaz0n': 'amazon',
            'micros0ft': 'microsoft', 'facebo0k': 'facebook', 'netfIix': 'netflix'
        }
        for typo, real in typosquat_patterns.items():
            if typo in self.domain.lower():
                suspicious_score += 35
                flags.append(f"Possible typosquatting of '{real}'")
        
        # Check URL length
        if len(self.url) > 75:
            suspicious_score += 10
            flags.append(f"Unusually long URL ({len(self.url)} characters)")
        
        self.results['checks']['suspicious_patterns'] = {
            'score': suspicious_score,
            'flags': flags
        }
        self.results['risk_score'] += suspicious_score
        
    def check_ssl_certificate(self):
        """Check SSL certificate validity"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    ssl_info = {
                        'valid': True,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'expires': cert['notAfter'],
                        'days_until_expiry': days_until_expiry
                    }
                    
                    if days_until_expiry < 30:
                        self.results['risk_score'] += 15
                        ssl_info['warning'] = "Certificate expires soon"
                    
                    cert_domain = ssl_info['subject'].get('commonName', '')
                    if cert_domain and self.domain not in cert_domain and not cert_domain.startswith('*'):
                        self.results['risk_score'] += 20
                        ssl_info['warning'] = "Certificate domain mismatch"
                    
                    self.results['checks']['ssl'] = ssl_info
        except Exception as e:
            self.results['checks']['ssl'] = {
                'valid': False,
                'error': str(e)
            }
            self.results['risk_score'] += 30
    
    def check_domain_age(self):
        """Check domain registration age"""
        try:
            domain_info = whois.whois(self.domain)
            creation_date = domain_info.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                    from datetime import timezone
                    now = datetime.now(timezone.utc)
                    age_days = (now - creation_date).days
                else:
                    age_days = (datetime.now() - creation_date).days
                
                domain_data = {
                    'creation_date': str(creation_date),
                    'age_days': age_days,
                    'registrar': domain_info.registrar,
                    'status': domain_info.status
                }
                
                if age_days < 30:
                    self.results['risk_score'] += 40
                    domain_data['warning'] = "Very new domain (< 30 days)"
                elif age_days < 180:
                    self.results['risk_score'] += 20
                    domain_data['warning'] = "Relatively new domain (< 6 months)"
                
                self.results['checks']['domain_age'] = domain_data
            else:
                self.results['checks']['domain_age'] = {'error': 'Could not determine age'}
                self.results['risk_score'] += 15
                
        except Exception as e:
            self.results['checks']['domain_age'] = {'error': str(e)}
            self.results['risk_score'] += 15
    
    def check_dns_records(self):
        """Check DNS records"""
        try:
            resolver = dns.resolver.Resolver()
            dns_info = {}
            
            try:
                a_records = resolver.resolve(self.domain, 'A')
                dns_info['A'] = [str(rdata) for rdata in a_records]
            except:
                dns_info['A'] = []
                self.results['risk_score'] += 20
            
            try:
                mx_records = resolver.resolve(self.domain, 'MX')
                dns_info['MX'] = [str(rdata.exchange) for rdata in mx_records]
            except:
                dns_info['MX'] = []
            
            try:
                txt_records = resolver.resolve(self.domain, 'TXT')
                dns_info['TXT'] = [str(rdata) for rdata in txt_records]
            except:
                dns_info['TXT'] = []
            
            try:
                ns_records = resolver.resolve(self.domain, 'NS')
                dns_info['NS'] = [str(rdata) for rdata in ns_records]
            except:
                dns_info['NS'] = []
            
            self.results['checks']['dns'] = dns_info
            
        except Exception as e:
            self.results['checks']['dns'] = {'error': str(e)}
            self.results['risk_score'] += 20
    
    def check_reputation(self):
        """Check domain reputation using basic heuristics"""
        reputation_score = 0
        flags = []
        
        if not self.url.startswith('https://'):
            reputation_score += 20
            flags.append("Not using HTTPS")
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']
        for tld in suspicious_tlds:
            if self.domain.endswith(tld):
                reputation_score += 25
                flags.append(f"Suspicious TLD: {tld}")
                break
        
        parsed = urlparse(self.url if self.url.startswith('http') else 'http://' + self.url)
        if parsed.port and parsed.port not in [80, 443]:
            reputation_score += 15
            flags.append(f"Non-standard port: {parsed.port}")
        
        self.results['checks']['reputation'] = {
            'score': reputation_score,
            'flags': flags
        }
        self.results['risk_score'] += reputation_score
    
    def check_virustotal(self):
        """Check URL against VirusTotal database"""
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            self.results['osint']['virustotal'] = {
                'status': 'skipped',
                'message': 'No API key provided'
            }
            return
        
        try:
            import base64
            url_id = base64.urlsafe_b64encode(self.url.encode()).decode().strip("=")
            
            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }
            
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total_scans = sum(stats.values())
                
                vt_score = 0
                if malicious > 0:
                    vt_score = min(malicious * 10, 50)
                if suspicious > 0:
                    vt_score += min(suspicious * 5, 25)
                
                self.results['osint']['virustotal'] = {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total_scans': total_scans,
                    'detection_rate': f"{malicious}/{total_scans}"
                }
                
                self.results['risk_score'] += vt_score
                
            elif response.status_code == 404:
                self.results['osint']['virustotal'] = {
                    'status': 'not_found',
                    'message': 'URL not in VirusTotal database'
                }
            else:
                self.results['osint']['virustotal'] = {
                    'status': 'error',
                    'message': f'API returned status {response.status_code}'
                }
                
        except Exception as e:
            self.results['osint']['virustotal'] = {
                'status': 'error',
                'message': str(e)
            }
    
    def check_shodan(self):
        """Check IP/domain against Shodan for open ports and vulnerabilities"""
        api_key = self.api_keys.get('shodan')
        if not api_key:
            self.results['osint']['shodan'] = {
                'status': 'skipped',
                'message': 'No API key provided'
            }
            return
        
        try:
            # Get IP address first
            ip_address = socket.gethostbyname(self.domain)
            
            response = requests.get(
                f"https://api.shodan.io/shodan/host/{ip_address}",
                params={'key': api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                shodan_info = {
                    'ip': ip_address,
                    'org': data.get('org', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'country': data.get('country_name', 'Unknown'),
                    'open_ports': data.get('ports', []),
                    'vulnerabilities': data.get('vulns', []),
                    'tags': data.get('tags', [])
                }
                
                # Risk scoring
                vuln_count = len(shodan_info['vulnerabilities'])
                if vuln_count > 0:
                    vuln_score = min(vuln_count * 15, 45)
                    self.results['risk_score'] += vuln_score
                    shodan_info['warning'] = f"Found {vuln_count} known vulnerabilities"
                
                # Suspicious open ports
                suspicious_ports = [21, 23, 3389, 5900, 5432, 27017]
                found_suspicious = [p for p in shodan_info['open_ports'] if p in suspicious_ports]
                if found_suspicious:
                    self.results['risk_score'] += 10
                    shodan_info['suspicious_ports'] = found_suspicious
                
                self.results['osint']['shodan'] = shodan_info
            else:
                self.results['osint']['shodan'] = {
                    'status': 'error',
                    'message': f'API returned status {response.status_code}'
                }
                
        except Exception as e:
            self.results['osint']['shodan'] = {
                'status': 'error',
                'message': str(e)
            }
    
    def check_haveibeenpwned(self):
        """Check if domain appears in data breaches"""
        api_key = self.api_keys.get('hibp')
        if not api_key:
            self.results['osint']['haveibeenpwned'] = {
                'status': 'skipped',
                'message': 'No API key provided'
            }
            return
        
        try:
            headers = {
                'hibp-api-key': api_key,
                'user-agent': 'PhishHunter-OSINT'
            }
            
            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breaches?domain={self.domain}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                breaches = response.json()
                
                hibp_info = {
                    'breach_count': len(breaches),
                    'breaches': []
                }
                
                for breach in breaches[:5]:  # Top 5 breaches
                    hibp_info['breaches'].append({
                        'name': breach.get('Name'),
                        'date': breach.get('BreachDate'),
                        'compromised_accounts': breach.get('PwnCount'),
                        'data_classes': breach.get('DataClasses', [])
                    })
                
                if len(breaches) > 0:
                    breach_score = min(len(breaches) * 5, 30)
                    self.results['risk_score'] += breach_score
                    hibp_info['warning'] = f"Domain involved in {len(breaches)} data breaches"
                
                self.results['osint']['haveibeenpwned'] = hibp_info
                
            elif response.status_code == 404:
                self.results['osint']['haveibeenpwned'] = {
                    'status': 'clean',
                    'message': 'No breaches found for this domain'
                }
            else:
                self.results['osint']['haveibeenpwned'] = {
                    'status': 'error',
                    'message': f'API returned status {response.status_code}'
                }
                
        except Exception as e:
            self.results['osint']['haveibeenpwned'] = {
                'status': 'error',
                'message': str(e)
            }
    
    def check_urlscan(self):
        """Submit URL to URLScan.io for analysis"""
        api_key = self.api_keys.get('urlscan')
        if not api_key:
            self.results['osint']['urlscan'] = {
                'status': 'skipped',
                'message': 'No API key provided'
            }
            return
        
        try:
            headers = {
                'API-Key': api_key,
                'Content-Type': 'application/json'
            }
            
            # Submit URL for scanning
            response = requests.post(
                'https://urlscan.io/api/v1/scan/',
                headers=headers,
                json={'url': self.url, 'visibility': 'private'},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                urlscan_info = {
                    'status': 'submitted',
                    'scan_id': data.get('uuid'),
                    'result_url': data.get('result'),
                    'message': 'Scan submitted successfully'
                }
                
                self.results['osint']['urlscan'] = urlscan_info
            else:
                self.results['osint']['urlscan'] = {
                    'status': 'error',
                    'message': f'API returned status {response.status_code}'
                }
                
        except Exception as e:
            self.results['osint']['urlscan'] = {
                'status': 'error',
                'message': str(e)
            }
    
    def check_alienvault(self):
        """Check AlienVault OTX for threat intelligence"""
        try:
            headers = {'X-OTX-API-KEY': self.api_keys.get('alienvault', '')}
            
            response = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/general",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                
                otx_info = {
                    'pulse_count': pulse_count,
                    'reputation': 'Unknown'
                }
                
                if pulse_count > 0:
                    threat_score = min(pulse_count * 10, 40)
                    self.results['risk_score'] += threat_score
                    otx_info['warning'] = f"Found in {pulse_count} threat intelligence pulses"
                    otx_info['reputation'] = 'Malicious'
                else:
                    otx_info['reputation'] = 'Clean'
                
                self.results['osint']['alienvault_otx'] = otx_info
            else:
                self.results['osint']['alienvault_otx'] = {
                    'status': 'error',
                    'message': f'API returned status {response.status_code}'
                }
                
        except Exception as e:
            self.results['osint']['alienvault_otx'] = {
                'status': 'error',
                'message': str(e)
            }
    
    def analyze(self, verbose=True):
        """Run all checks"""
        if verbose:
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f"{Fore.CYAN}PhishHunter OSINT Analysis Report")
            print(f"{Fore.CYAN}{'='*60}\n")
            print(f"{Fore.WHITE}Analyzing: {Fore.YELLOW}{self.url}")
            print(f"{Fore.WHITE}Domain: {Fore.YELLOW}{self.domain}\n")
        
        # Standard checks
        standard_checks = [
            ("Checking suspicious patterns", self.check_suspicious_patterns),
            ("Checking SSL certificate", self.check_ssl_certificate),
            ("Checking domain age", self.check_domain_age),
            ("Checking DNS records", self.check_dns_records),
            ("Checking reputation", self.check_reputation),
        ]
        
        # OSINT checks
        osint_checks = [
            ("VirusTotal scan", self.check_virustotal, 'virustotal'),
            ("Shodan lookup", self.check_shodan, 'shodan'),
            ("HaveIBeenPwned check", self.check_haveibeenpwned, 'hibp'),
            ("URLScan.io submission", self.check_urlscan, 'urlscan'),
            ("AlienVault OTX check", self.check_alienvault, 'alienvault'),
        ]
        
        for message, check_func in standard_checks:
            if verbose:
                print(f"{Fore.BLUE}[*] {message}...")
            check_func()
        
        if verbose:
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f"{Fore.CYAN}OSINT Intelligence Gathering")
            print(f"{Fore.CYAN}{'='*60}\n")
        
        for message, check_func, key in osint_checks:
            if self.api_keys.get(key):
                if verbose:
                    print(f"{Fore.GREEN}[OSINT] {message}...")
                check_func()
                time.sleep(0.5)  # Rate limiting
        
        if verbose:
            self.generate_report()
        
        return self.results
        
    def generate_report(self):
        """Generate final report"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}Analysis Results")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        risk_score = min(self.results['risk_score'], 100)
        if risk_score >= 70:
            risk_level = "HIGH"
            color = Fore.RED
            icon = "⚠️"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
            color = Fore.YELLOW
            icon = "⚠"
        else:
            risk_level = "LOW"
            color = Fore.GREEN
            icon = "✓"
        
        print(f"{Fore.WHITE}Risk Score: {color}{risk_score}/100")
        print(f"{Fore.WHITE}Risk Level: {color}{icon} {risk_level}\n")
        
        # Standard checks
        print(f"{Fore.CYAN}STANDARD SECURITY CHECKS")
        print(f"{Fore.CYAN}{'-'*60}\n")
        
        for check_name, check_data in self.results['checks'].items():
            print(f"{Fore.CYAN}▶ {check_name.upper().replace('_', ' ')}")
            if isinstance(check_data, dict):
                for key, value in check_data.items():
                    if key == 'flags' and value:
                        for flag in value:
                            print(f"  {Fore.RED}⚠ {flag}")
                    elif key == 'error':
                        print(f"  {Fore.YELLOW}⚠ Error: {value}")
                    elif key == 'warning':
                        print(f"  {Fore.YELLOW}⚠ Warning: {value}")
                    elif key not in ['score', 'flags']:
                        if isinstance(value, list) and len(value) > 3:
                            print(f"  {Fore.WHITE}{key}: {value[:3]}... ({len(value)} total)")
                        else:
                            print(f"  {Fore.WHITE}{key}: {value}")
            print()
        
        # OSINT intelligence
        if self.results['osint']:
            print(f"{Fore.CYAN}OSINT INTELLIGENCE")
            print(f"{Fore.CYAN}{'-'*60}\n")
            
            for osint_name, osint_data in self.results['osint'].items():
                print(f"{Fore.GREEN}▶ {osint_name.upper().replace('_', ' ')}")
                if isinstance(osint_data, dict):
                    for key, value in osint_data.items():
                        if key == 'warning':
                            print(f"  {Fore.RED}⚠ {value}")
                        elif key == 'error':
                            print(f"  {Fore.YELLOW}⚠ Error: {value}")
                        elif key == 'status' and value == 'skipped':
                            print(f"  {Fore.YELLOW}ℹ Skipped - No API key")
                        elif key not in ['status']:
                            if isinstance(value, list) and len(value) > 5:
                                print(f"  {Fore.WHITE}{key}: {value[:5]}... ({len(value)} total)")
                            else:
                                print(f"  {Fore.WHITE}{key}: {value}")
                print()
        
        # Recommendation
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}RECOMMENDATION")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        if risk_score >= 70:
            print(f"{Fore.RED}⚠️  HIGH RISK - This URL shows multiple signs of phishing.")
            print(f"{Fore.RED}   DO NOT proceed with this website.")
            print(f"{Fore.RED}   Do not enter any credentials or personal information.")
        elif risk_score >= 40:
            print(f"{Fore.YELLOW}⚠  MEDIUM RISK - Exercise caution with this URL.")
            print(f"{Fore.YELLOW}   Verify legitimacy before entering sensitive information.")
            print(f"{Fore.YELLOW}   Check the domain carefully for typos.")
        else:
            print(f"{Fore.GREEN}✓  LOW RISK - This URL appears relatively safe.")
            print(f"{Fore.GREEN}   However, always verify URLs before entering credentials.")
        
        print(f"\n{Fore.CYAN}{'='*60}\n")

def batch_analyze(urls, api_keys=None, output_file=None):
    """Analyze multiple URLs"""
    results = []
    total = len(urls)
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Batch Analysis Mode with OSINT")
    print(f"{Fore.CYAN}Total URLs: {total}")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    for i, url in enumerate(urls, 1):
        print(f"{Fore.BLUE}[{i}/{total}] Analyzing: {url}")
        
        hunter = PhishHunter(url.strip(), api_keys)
        result = hunter.analyze(verbose=False)
        results.append(result)
        
        risk_score = min(result['risk_score'], 100)
        if risk_score >= 70:
            print(f"{Fore.RED}  └─ HIGH RISK ({risk_score}/100)\n")
        elif risk_score >= 40:
            print(f"{Fore.YELLOW}  └─ MEDIUM RISK ({risk_score}/100)\n")
        else:
            print(f"{Fore.GREEN}  └─ LOW RISK ({risk_score}/100)\n")
        
        if i < total:
            time.sleep(2)  # Rate limiting for API calls
    
    # Summary
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Batch Analysis Summary")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    high_risk = sum(1 for r in results if r['risk_score'] >= 70)
    medium_risk = sum(1 for r in results if 40 <= r['risk_score'] < 70)
    low_risk = sum(1 for r in results if r['risk_score'] < 40)
    
    print(f"{Fore.RED}High Risk: {high_risk}")
    print(f"{Fore.YELLOW}Medium Risk: {medium_risk}")
    print(f"{Fore.GREEN}Low Risk: {low_risk}\n")
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"{Fore.GREEN}Results saved to {output_file}\n")
    
    return results

def main():
    parser = argparse.ArgumentParser(
        description='PhishHunter: Enhanced Phishing Detection with OSINT Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single URL with OSINT:
    python phishhunter.py -u https://suspicious-site.com \\
        --vt YOUR_VT_KEY \\
        --shodan YOUR_SHODAN_KEY \\
        --hibp YOUR_HIBP_KEY
  
  Batch mode:
    python phishhunter.py -b urls.txt --vt YOUR_VT_KEY -j results.json
  
API Keys (Get from):
  VirusTotal: https://www.virustotal.com/gui/sign-in
  Shodan: https://account.shodan.io/
  HaveIBeenPwned: https://haveibeenpwned.com/API/Key
  URLScan.io: https://urlscan.io/user/signup
  AlienVault OTX: https://otx.alienvault.com/ (free)
  
Environment Variables:
  VT_API_KEY, SHODAN_API_KEY, HIBP_API_KEY, URLSCAN_API_KEY, ALIENVAULT_API_KEY
        """
    )
    
    parser.add_argument('-u', '--url', help='Single URL to analyze')
    parser.add_argument('-b', '--batch', help='File containing URLs (one per line)')
    parser.add_argument('--vt', '--virustotal', dest='vt_key', help='VirusTotal API key')
    parser.add_argument('--shodan', dest='shodan_key', help='Shodan API key')
    parser.add_argument('--hibp', dest='hibp_key', help='HaveIBeenPwned API key')
    parser.add_argument('--urlscan', dest='urlscan_key', help='URLScan.io API key')
    parser.add_argument('--alienvault', dest='alienvault_key', help='AlienVault OTX API key')
    parser.add_argument('-j', '--json', help='Output results to JSON file')
    parser.add_argument('--no-osint', action='store_true', help='Skip OSINT checks')
    
    args = parser.parse_args()
    
    # Collect API keys from args and environment
    api_keys = {
        'virustotal': args.vt_key or os.environ.get('VT_API_KEY'),
        'shodan': args.shodan_key or os.environ.get('SHODAN_API_KEY'),
        'hibp': args.hibp_key or os.environ.get('HIBP_API_KEY'),
        'urlscan': args.urlscan_key or os.environ.get('URLSCAN_API_KEY'),
        'alienvault': args.alienvault_key or os.environ.get('ALIENVAULT_API_KEY')
    }
    
    # Remove None values
    api_keys = {k: v for k, v in api_keys.items() if v}
    
    if args.no_osint:
        api_keys = {}
    
    # Display OSINT status
    if api_keys and not args.batch:
        print(f"\n{Fore.CYAN}OSINT Integration Status:")
        for service, key in api_keys.items():
            print(f"{Fore.GREEN}  ✓ {service.title()}: Enabled")
        print()
    
    try:
        if args.batch:
            with open(args.batch, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            batch_analyze(urls, api_keys, args.json)
            
        elif args.url:
            hunter = PhishHunter(args.url, api_keys)
            hunter.analyze()
            
            if args.json:
                with open(args.json, 'w') as f:
                    json.dump(hunter.results, f, indent=2, default=str)
                print(f"{Fore.GREEN}Results saved to {args.json}")
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Analysis interrupted by user.")
    except FileNotFoundError as e:
        print(f"\n{Fore.RED}Error: File not found - {e}")
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}")

if __name__ == "__main__":
    main()