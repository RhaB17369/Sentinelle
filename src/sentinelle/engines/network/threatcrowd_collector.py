"""
ThreatCrowd Collector
Collects threat intelligence (free, no API key required)
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
import requests


class ThreatCrowdCollector:
    """Collect threat intelligence from ThreatCrowd (free, no API key)"""
    
    BASE_URL = "https://www.threatcrowd.org/searchApi/v2"
    
    def __init__(self):
        """Initialize ThreatCrowd collector"""
        self.logger = logging.getLogger(__name__)
    
    def _make_request(self, resource_type: str, resource: str) -> Optional[Dict[str, Any]]:
        """Make API request to ThreatCrowd"""
        try:
            response = requests.get(
                f"{self.BASE_URL}/{resource_type}/report/",
                params={resource_type: resource},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == '1':
                    return data
                else:
                    self.logger.debug(f"No data found for {resource}")
                    return None
            else:
                self.logger.error(f"ThreatCrowd API error: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"ThreatCrowd request failed: {e}")
            return None
    
    def collect_domain(self, domain: str) -> Dict[str, Any]:
        """
        Collect threat intelligence on a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            Dictionary with ThreatCrowd intelligence
        """
        intelligence = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'source': 'threatcrowd',
            'resolutions': [],
            'emails': [],
            'subdomains': [],
            'hashes': [],
        }
        
        data = self._make_request('domain', domain)
        
        if data:
            # IP resolutions
            resolutions = data.get('resolutions', [])
            intelligence['resolutions'] = [
                {
                    'ip': r.get('ip_address'),
                    'last_resolved': r.get('last_resolved')
                }
                for r in resolutions[:10]  # Top 10
            ]
            
            # Associated emails
            intelligence['emails'] = data.get('emails', [])[:5]  # Top 5
            
            # Subdomains
            intelligence['subdomains'] = data.get('subdomains', [])[:10]  # Top 10
            
            # Associated malware hashes
            intelligence['hashes'] = data.get('hashes', [])[:5]  # Top 5
            
            self.logger.info(f"ThreatCrowd data collected for domain {domain}")
        
        return intelligence
    
    def collect_ip(self, ip: str) -> Dict[str, Any]:
        """
        Collect threat intelligence on an IP address.
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary with ThreatCrowd intelligence
        """
        intelligence = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'source': 'threatcrowd',
            'resolutions': [],
            'hashes': [],
        }
        
        data = self._make_request('ip', ip)
        
        if data:
            # Domain resolutions
            resolutions = data.get('resolutions', [])
            intelligence['resolutions'] = [
                {
                    'domain': r.get('domain'),
                    'last_resolved': r.get('last_resolved')
                }
                for r in resolutions[:10]
            ]
            
            # Associated malware hashes
            intelligence['hashes'] = data.get('hashes', [])[:5]
            
            self.logger.info(f"ThreatCrowd data collected for IP {ip}")
        
        return intelligence
    
    def collect_email(self, email: str) -> Dict[str, Any]:
        """
        Collect intelligence on an email address.
        
        Args:
            email: Email address
            
        Returns:
            Dictionary with ThreatCrowd intelligence
        """
        intelligence = {
            'email': email,
            'timestamp': datetime.now().isoformat(),
            'source': 'threatcrowd',
            'domains': [],
        }
        
        data = self._make_request('email', email)
        
        if data:
            # Associated domains
            intelligence['domains'] = data.get('domains', [])[:10]
            
            self.logger.info(f"ThreatCrowd data collected for email {email}")
        
        return intelligence
