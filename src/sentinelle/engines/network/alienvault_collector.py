"""
AlienVault OTX (Open Threat Exchange) Collector
Collects threat intelligence from community-driven platform
"""

import os
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import requests


class AlienVaultCollector:
    """Collect threat intelligence from AlienVault OTX"""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize AlienVault OTX collector.
        
        Args:
            api_key: OTX API key (or use OTX_API_KEY env var)
        """
        self.logger = logging.getLogger(__name__)
        self.api_key = api_key or os.getenv('OTX_API_KEY')
        
        if not self.api_key:
            self.logger.warning(
                "AlienVault OTX API key not found. "
                "Set OTX_API_KEY environment variable or pass api_key parameter."
            )
    
    def _make_request(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Make API request to OTX"""
        if not self.api_key:
            return None
        
        headers = {
            'X-OTX-API-KEY': self.api_key
        }
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/{endpoint}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                self.logger.debug(f"Resource not found: {endpoint}")
                return None
            else:
                self.logger.error(f"OTX API error: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"OTX request failed: {e}")
            return None
    
    def collect_domain(self, domain: str) -> Dict[str, Any]:
        """
        Collect threat intelligence on a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            Dictionary with OTX intelligence
        """
        intelligence = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'source': 'alienvault_otx',
            'general': None,
            'pulses': [],
            'malware': None,
            'url_list': None,
        }
        
        if not self.api_key:
            intelligence['error'] = 'API key not configured'
            return intelligence
        
        # General info
        general = self._make_request(f"indicators/domain/{domain}/general")
        if general:
            intelligence['general'] = {
                'pulse_count': general.get('pulse_info', {}).get('count', 0),
                'alexa_rank': general.get('alexa'),
                'whois': general.get('whois'),
            }
        
        # Pulses (threat intelligence reports)
        pulses = self._make_request(f"indicators/domain/{domain}/pulses")
        if pulses and 'results' in pulses:
            intelligence['pulses'] = [
                {
                    'name': p.get('name'),
                    'description': p.get('description'),
                    'tags': p.get('tags', []),
                    'created': p.get('created'),
                    'modified': p.get('modified'),
                    'tlp': p.get('TLP'),
                }
                for p in pulses['results'][:5]  # Top 5 pulses
            ]
        
        # Malware samples
        malware = self._make_request(f"indicators/domain/{domain}/malware")
        if malware and 'data' in malware:
            intelligence['malware'] = {
                'count': len(malware['data']),
                'samples': [
                    {
                        'hash': m.get('hash'),
                        'detections': m.get('detections'),
                    }
                    for m in malware['data'][:3]  # Top 3 samples
                ]
            }
        
        # URL list
        url_list = self._make_request(f"indicators/domain/{domain}/url_list")
        if url_list and 'url_list' in url_list:
            intelligence['url_list'] = {
                'count': len(url_list['url_list']),
                'urls': url_list['url_list'][:5]  # Top 5 URLs
            }
        
        self.logger.info(f"AlienVault OTX data collected for domain {domain}")
        
        return intelligence
    
    def collect_ip(self, ip: str) -> Dict[str, Any]:
        """
        Collect threat intelligence on an IP address.
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary with OTX intelligence
        """
        intelligence = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'source': 'alienvault_otx',
            'general': None,
            'pulses': [],
            'malware': None,
            'reputation': None,
        }
        
        if not self.api_key:
            intelligence['error'] = 'API key not configured'
            return intelligence
        
        # General info
        general = self._make_request(f"indicators/IPv4/{ip}/general")
        if general:
            intelligence['general'] = {
                'pulse_count': general.get('pulse_info', {}).get('count', 0),
                'country': general.get('country_name'),
                'city': general.get('city'),
                'asn': general.get('asn'),
            }
        
        # Reputation
        reputation = self._make_request(f"indicators/IPv4/{ip}/reputation")
        if reputation:
            intelligence['reputation'] = {
                'reputation': reputation.get('reputation'),
                'threat_score': reputation.get('threat_score'),
                'activities': reputation.get('activities', [])[:5]
            }
        
        # Pulses
        pulses = self._make_request(f"indicators/IPv4/{ip}/pulses")
        if pulses and 'results' in pulses:
            intelligence['pulses'] = [
                {
                    'name': p.get('name'),
                    'description': p.get('description'),
                    'tags': p.get('tags', []),
                    'created': p.get('created'),
                }
                for p in pulses['results'][:5]
            ]
        
        # Malware
        malware = self._make_request(f"indicators/IPv4/{ip}/malware")
        if malware and 'data' in malware:
            intelligence['malware'] = {
                'count': len(malware['data']),
                'samples': [m.get('hash') for m in malware['data'][:3]]
            }
        
        self.logger.info(f"AlienVault OTX data collected for IP {ip}")
        
        return intelligence
