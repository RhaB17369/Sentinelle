"""
Domain/website OSINT collector.
Gathers intelligence from WHOIS, DNS, SSL certificates, and HTTP headers.
"""

import whois
import dns.resolver
import ssl
import socket
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
from urllib.parse import urlparse


class DomainCollector:
    """Collect OSINT intelligence on domains and websites"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5
    
    def collect(self, domain: str) -> Dict[str, Any]:
        """
        Collect all available intelligence on a domain.
        
        Args:
            domain: Domain name to investigate
            
        Returns:
            Dictionary containing all collected intelligence
        """
        intelligence = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'whois': self._collect_whois(domain),
            'dns': self._collect_dns(domain),
            'ssl_certificate': self._collect_ssl_cert(domain),
            'http_headers': self._collect_http_headers(domain),
            'technologies': self._detect_technologies(domain),
        }
        
        return intelligence
    
    def _collect_whois(self, domain: str) -> Optional[Dict[str, Any]]:
        """Collect WHOIS data"""
        try:
            w = whois.whois(domain)
            
            # Extract relevant fields
            whois_data = {
                'registrar': w.registrar if hasattr(w, 'registrar') else None,
                'creation_date': str(w.creation_date) if hasattr(w, 'creation_date') else None,
                'expiration_date': str(w.expiration_date) if hasattr(w, 'expiration_date') else None,
                'updated_date': str(w.updated_date) if hasattr(w, 'updated_date') else None,
                'name_servers': w.name_servers if hasattr(w, 'name_servers') else None,
                'status': w.status if hasattr(w, 'status') else None,
                'emails': w.emails if hasattr(w, 'emails') else None,
                'org': w.org if hasattr(w, 'org') else None,
                'country': w.country if hasattr(w, 'country') else None,
            }
            
            self.logger.info(f"WHOIS data collected for {domain}")
            return whois_data
            
        except Exception as e:
            self.logger.warning(f"Failed to collect WHOIS for {domain}: {e}")
            return None
    
    def _collect_dns(self, domain: str) -> Dict[str, List[str]]:
        """Collect DNS records"""
        dns_data = {}
        
        # Record types to query
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = self.dns_resolver.resolve(domain, record_type)
                dns_data[record_type] = [str(rdata) for rdata in answers]
                self.logger.debug(f"DNS {record_type} records collected for {domain}")
            except dns.resolver.NoAnswer:
                dns_data[record_type] = []
            except dns.resolver.NXDOMAIN:
                self.logger.warning(f"Domain {domain} does not exist")
                dns_data[record_type] = []
            except Exception as e:
                self.logger.warning(f"Failed to query {record_type} for {domain}: {e}")
                dns_data[record_type] = []
        
        return dns_data
    
    def _collect_ssl_cert(self, domain: str) -> Optional[Dict[str, Any]]:
        """Collect SSL/TLS certificate information"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    cert_data = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'subject_alt_names': [x[1] for x in cert.get('subjectAltName', [])],
                    }
                    
                    self.logger.info(f"SSL certificate collected for {domain}")
                    return cert_data
                    
        except Exception as e:
            self.logger.warning(f"Failed to collect SSL cert for {domain}: {e}")
            return None
    
    def _collect_http_headers(self, domain: str) -> Optional[Dict[str, Any]]:
        """Collect HTTP headers and response information"""
        try:
            # Try HTTPS first
            for scheme in ['https', 'http']:
                url = f"{scheme}://{domain}"
                try:
                    response = requests.get(
                        url,
                        timeout=10,
                        allow_redirects=True,
                        headers={'User-Agent': 'SENTINNELLE/1.0 (OSINT Intelligence Platform)'}
                    )
                    
                    headers_data = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'final_url': response.url,
                        'redirect_chain': [r.url for r in response.history],
                        'scheme': scheme,
                    }
                    
                    self.logger.info(f"HTTP headers collected for {domain} via {scheme}")
                    return headers_data
                    
                except requests.exceptions.RequestException:
                    continue
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Failed to collect HTTP headers for {domain}: {e}")
            return None
    
    def _detect_technologies(self, domain: str) -> List[str]:
        """Detect technologies used by the website (simplified Wappalyzer-style)"""
        technologies = []
        
        try:
            url = f"https://{domain}"
            response = requests.get(
                url,
                timeout=10,
                headers={'User-Agent': 'SENTINNELLE/1.0 (OSINT Intelligence Platform)'}
            )
            
            headers = response.headers
            body = response.text.lower()
            
            # Server detection
            if 'server' in headers:
                server = headers['server']
                technologies.append(f"Server: {server}")
            
            # Framework detection (simplified)
            if 'x-powered-by' in headers:
                technologies.append(f"Powered by: {headers['x-powered-by']}")
            
            # CMS detection (very basic)
            cms_signatures = {
                'wordpress': ['wp-content', 'wp-includes'],
                'drupal': ['drupal.js', 'sites/default'],
                'joomla': ['joomla', 'com_content'],
                'django': ['csrfmiddlewaretoken'],
                'flask': ['werkzeug'],
            }
            
            for cms, signatures in cms_signatures.items():
                if any(sig in body for sig in signatures):
                    technologies.append(f"CMS: {cms}")
            
            # JavaScript libraries (basic detection)
            js_libraries = {
                'jquery': 'jquery',
                'react': 'react',
                'angular': 'angular',
                'vue': 'vue.js',
                'bootstrap': 'bootstrap',
            }
            
            for lib, signature in js_libraries.items():
                if signature in body:
                    technologies.append(f"JS Library: {lib}")
            
            self.logger.info(f"Technologies detected for {domain}: {technologies}")
            
        except Exception as e:
            self.logger.warning(f"Failed to detect technologies for {domain}: {e}")
        
        return technologies
    
    def get_domain_age(self, whois_data: Optional[Dict]) -> Optional[int]:
        """Calculate domain age in days from WHOIS data"""
        if not whois_data or not whois_data.get('creation_date'):
            return None
        
        try:
            creation_date_str = whois_data['creation_date']
            # Handle list of dates (take first)
            if isinstance(creation_date_str, list):
                creation_date_str = creation_date_str[0]
            
            # Parse date string
            if isinstance(creation_date_str, str):
                # This is simplified - in production, handle various date formats
                creation_date = datetime.fromisoformat(creation_date_str.replace(' ', 'T'))
            else:
                creation_date = creation_date_str
            
            age = (datetime.now() - creation_date).days
            return age
            
        except Exception as e:
            self.logger.warning(f"Failed to calculate domain age: {e}")
            return None
