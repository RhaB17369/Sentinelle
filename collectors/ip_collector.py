"""
IP address and network OSINT collector.
Gathers intelligence from ASN, geolocation, reverse DNS, and threat intelligence.
"""

import socket
import ipaddress
from ipwhois import IPWhois
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
import requests


class IPCollector:
    """Collect OSINT intelligence on IP addresses and networks"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def collect(self, ip: str) -> Dict[str, Any]:
        """
        Collect all available intelligence on an IP address.
        
        Args:
            ip: IP address to investigate
            
        Returns:
            Dictionary containing all collected intelligence
        """
        intelligence = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'type': self._get_ip_type(ip),
            'whois': self._collect_whois(ip),
            'reverse_dns': self._collect_reverse_dns(ip),
            'geolocation': self._collect_geolocation(ip),
            'asn': self._collect_asn(ip),
        }
        
        return intelligence
    
    def _get_ip_type(self, ip: str) -> str:
        """Determine IP address type"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            if ip_obj.is_private:
                return "private"
            elif ip_obj.is_loopback:
                return "loopback"
            elif ip_obj.is_multicast:
                return "multicast"
            elif ip_obj.is_reserved:
                return "reserved"
            else:
                return "public"
                
        except Exception as e:
            self.logger.warning(f"Failed to determine IP type for {ip}: {e}")
            return "unknown"
    
    def _collect_whois(self, ip: str) -> Optional[Dict[str, Any]]:
        """Collect WHOIS data for IP"""
        try:
            obj = IPWhois(ip)
            results = obj.lookup_rdap(depth=1)
            
            whois_data = {
                'asn': results.get('asn'),
                'asn_cidr': results.get('asn_cidr'),
                'asn_country_code': results.get('asn_country_code'),
                'asn_description': results.get('asn_description'),
                'network': results.get('network', {}),
                'objects': results.get('objects', {}),
            }
            
            self.logger.info(f"WHOIS data collected for IP {ip}")
            return whois_data
            
        except Exception as e:
            self.logger.warning(f"Failed to collect WHOIS for IP {ip}: {e}")
            return None
    
    def _collect_reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            self.logger.info(f"Reverse DNS for {ip}: {hostname}")
            return hostname
        except Exception as e:
            self.logger.debug(f"No reverse DNS for {ip}: {e}")
            return None
    
    def _collect_geolocation(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Collect geolocation data for IP.
        Uses ip-api.com (free, no API key required, rate limited).
        
        Note: Geolocation is probabilistic and city-level accuracy at best.
        """
        try:
            # Using ip-api.com free tier (45 requests/minute)
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    geo_data = {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'note': 'Geolocation is probabilistic with city-level accuracy at best',
                    }
                    
                    self.logger.info(f"Geolocation collected for IP {ip}")
                    return geo_data
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Failed to collect geolocation for IP {ip}: {e}")
            return None
    
    def _collect_asn(self, ip: str) -> Optional[Dict[str, Any]]:
        """Collect ASN (Autonomous System Number) information"""
        try:
            obj = IPWhois(ip)
            results = obj.lookup_rdap(depth=1)
            
            asn_data = {
                'asn': results.get('asn'),
                'asn_cidr': results.get('asn_cidr'),
                'asn_country_code': results.get('asn_country_code'),
                'asn_description': results.get('asn_description'),
                'asn_date': results.get('asn_date'),
                'asn_registry': results.get('asn_registry'),
            }
            
            self.logger.info(f"ASN data collected for IP {ip}")
            return asn_data
            
        except Exception as e:
            self.logger.warning(f"Failed to collect ASN for IP {ip}: {e}")
            return None
