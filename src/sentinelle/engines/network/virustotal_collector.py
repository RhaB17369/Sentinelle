"""
VirusTotal OSINT Collector
Collects threat intelligence from VirusTotal API
"""

import os
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import requests


class VirusTotalCollector:
    """Collect threat intelligence from VirusTotal"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal collector.
        
        Args:
            api_key: VirusTotal API key (or use VT_API_KEY env var)
        """
        self.logger = logging.getLogger(__name__)
        self.api_key = api_key or os.getenv('VT_API_KEY')
        
        if not self.api_key:
            self.logger.warning(
                "VirusTotal API key not found. "
                "Set VT_API_KEY environment variable or pass api_key parameter."
            )
    
    def _make_request(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Make API request to VirusTotal"""
        if not self.api_key:
            return None
        
        headers = {
            'x-apikey': self.api_key
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
            elif response.status_code == 429:
                self.logger.warning("VirusTotal rate limit exceeded")
                return None
            else:
                self.logger.error(f"VirusTotal API error: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"VirusTotal request failed: {e}")
            return None
    
    def collect_domain(self, domain: str) -> Dict[str, Any]:
        """
        Collect intelligence on a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            Dictionary with VirusTotal intelligence
        """
        intelligence = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'source': 'virustotal',
            'report': None,
            'reputation': None,
            'categories': None,
            'last_analysis': None,
        }
        
        if not self.api_key:
            intelligence['error'] = 'API key not configured'
            return intelligence
        
        # Get domain report
        data = self._make_request(f"domains/{domain}")
        
        if data and 'data' in data:
            attributes = data['data'].get('attributes', {})
            
            intelligence['report'] = {
                'reputation': attributes.get('reputation'),
                'popularity_ranks': attributes.get('popularity_ranks'),
                'categories': attributes.get('categories'),
                'last_analysis_stats': attributes.get('last_analysis_stats'),
                'last_analysis_date': attributes.get('last_analysis_date'),
                'creation_date': attributes.get('creation_date'),
                'whois': attributes.get('whois'),
            }
            
            # Reputation score
            reputation = attributes.get('reputation', 0)
            intelligence['reputation'] = {
                'score': reputation,
                'level': self._get_reputation_level(reputation)
            }
            
            # Categories
            categories = attributes.get('categories', {})
            intelligence['categories'] = categories
            
            # Last analysis
            stats = attributes.get('last_analysis_stats', {})
            intelligence['last_analysis'] = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
            }
            
            self.logger.info(f"VirusTotal data collected for domain {domain}")
        
        return intelligence
    
    def collect_ip(self, ip: str) -> Dict[str, Any]:
        """
        Collect intelligence on an IP address.
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary with VirusTotal intelligence
        """
        intelligence = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'source': 'virustotal',
            'report': None,
            'reputation': None,
            'last_analysis': None,
        }
        
        if not self.api_key:
            intelligence['error'] = 'API key not configured'
            return intelligence
        
        # Get IP report
        data = self._make_request(f"ip_addresses/{ip}")
        
        if data and 'data' in data:
            attributes = data['data'].get('attributes', {})
            
            intelligence['report'] = {
                'reputation': attributes.get('reputation'),
                'country': attributes.get('country'),
                'asn': attributes.get('asn'),
                'as_owner': attributes.get('as_owner'),
                'network': attributes.get('network'),
                'last_analysis_stats': attributes.get('last_analysis_stats'),
            }
            
            # Reputation
            reputation = attributes.get('reputation', 0)
            intelligence['reputation'] = {
                'score': reputation,
                'level': self._get_reputation_level(reputation)
            }
            
            # Last analysis
            stats = attributes.get('last_analysis_stats', {})
            intelligence['last_analysis'] = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
            }
            
            self.logger.info(f"VirusTotal data collected for IP {ip}")
        
        return intelligence
    
    def _get_reputation_level(self, score: int) -> str:
        """Convert reputation score to level"""
        if score >= 50:
            return "excellent"
        elif score >= 0:
            return "good"
        elif score >= -50:
            return "suspicious"
        else:
            return "malicious"
