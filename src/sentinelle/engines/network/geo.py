
import requests
import json
import logging
from typing import Dict, Any, Optional
from rich.console import Console
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

class GeoJSCollector:
    """
    Collector for GeoJS API (https://get.geojs.io/)
    Gathers detailed geolocation and network information.
    """
    BASE_URL = "https://get.geojs.io/v1/ip/geo/{ip}.json"
    PTR_URL = "https://get.geojs.io/v1/dns/ptr/{ip}.json"
    IP_URL = "https://get.geojs.io/v1/ip.json"

    def __init__(self):
        self.session = requests.Session()

    def get_my_ip(self) -> str:
        """Get public IP of the caller."""
        try:
            response = self.session.get(self.IP_URL, timeout=10)
            if response.status_code == 200:
                return response.json().get('ip')
            return "127.0.0.1"
        except Exception as e:
            logger.warning(f"Failed to get public IP: {e}")
            return "127.0.0.1"

    def get_geo_data(self, ip_address: str) -> Dict[str, Any]:
        """
        Get all available geodata for a specific IP address from GeoJS.
        """
        try:
            url = self.BASE_URL.format(ip=ip_address)
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                return response.json()
            return {}
        except Exception as e:
            logger.warning(f"GeoJS geo lookup failed for {ip_address}: {e}")
            return {}

    def get_ptr_data(self, ip_address: str) -> Optional[str]:
        """
        Get the DNS PTR record of an IP address via GeoJS.
        """
        try:
            url = self.PTR_URL.format(ip=ip_address)
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('ptr')
            return None
        except Exception as e:
            logger.debug(f"GeoJS PTR lookup failed for {ip_address}: {e}")
            return None

    def collect_enriched(self, ip_address: str) -> Dict[str, Any]:
        """
        Collect and format enriched data from GeoJS
        """
        raw_data = self.get_geo_data(ip_address)
        if not raw_data:
            return {}

        # Format into a clean structure compatible with IPCollector
        enriched = {
            'country': raw_data.get('country'),
            'country_code': raw_data.get('country_code'),
            'country_code3': raw_data.get('country_code3'),
            'region': raw_data.get('region'),
            'city': raw_data.get('city'),
            'latitude': raw_data.get('latitude'),
            'longitude': raw_data.get('longitude'),
            'timezone': raw_data.get('timezone'),
            'isp': raw_data.get('organization_name'),
            'asn': raw_data.get('asn'),
            'organization': raw_data.get('organization'),
            'accuracy': raw_data.get('accuracy'),
            'continent_code': raw_data.get('continent_code'),
            'currency': raw_data.get('currency'),
            'area_code': raw_data.get('area_code'),
            'ptr': self.get_ptr_data(ip_address)
        }
        return enriched

# Standalone functions for direct use as requested in test.py

_collector = GeoJSCollector()

def getIP() -> str:
    """Get the current public IP address."""
    return _collector.get_my_ip()

def getGeoData(ip: str) -> Dict[str, Any]:
    """Get geodata for a specific IP."""
    return _collector.get_geo_data(ip)

def getCountry(ip: str, output_format: str = 'plain') -> Any:
    """Get country information for an IP."""
    data = _collector.get_geo_data(ip)
    country = data.get('country', 'Unknown')
    code = data.get('country_code', '??')
    
    if output_format == 'json':
        return json.dumps({'country': country, 'country_code': code})
    return country

def getPTR(ip: str) -> Optional[str]:
    """Get PTR record for an IP."""
    return _collector.get_ptr_data(ip)

def showIpDetails(ip: str):
    """Print detailed IP information in the requested format."""
    data = _collector.get_geo_data(ip)
    if not data:
        console.print(f"[red]No data found for IP: {ip}[/red]")
        return

    print("-" * 70)
    print("                             HOST DETAILS")
    print("-" * 70)
    
    # Define fields to display with their labels
    display_map = [
        ('Country', 'country'),
        ('Ip', 'ip'),
        ('Organization name', 'organization_name'),
        ('Asn', 'asn'),
        ('Organization', 'organization'),
        ('Area code', 'area_code'),
        ('Timezone', 'timezone'),
        ('Country code', 'country_code'),
        ('Country code3', 'country_code3'),
        ('Continent code', 'continent_code'),
        ('Accuracy', 'accuracy'),
        ('Longitude', 'longitude'),
        ('Latitude', 'latitude'),
        ('Region', 'region'),
        ('City', 'city'),
        ('Currency', 'currency')
    ]

    for label, key in display_map:
        val = data.get(key)
        if val is not None:
            print(f"{label:<50} {val}")
    
    # Add PTR record if available
    ptr = _collector.get_ptr_data(ip)
    if ptr:
        print(f"{'PTR Record':<50} {ptr}")
    
    print(f"{'Country':<50} {data.get('country', 'Unknown')}")
    print("-" * 70)

def showCountryDetails(ip: str):
    """Print detailed Country information in the requested format."""
    data = _collector.get_geo_data(ip)
    if not data:
        console.print(f"[red]No data found for IP: {ip}[/red]")
        return

    print("-" * 70)
    print("                            COUNTRY DETAILS")
    print("-" * 70)
    
    fields = [
        ('Country', 'country'),
        ('Country Code', 'country_code'),
        ('Country Code 3', 'country_code3'),
        ('Continent Code', 'continent_code'),
        ('Currency', 'currency'),
        ('Timezone', 'timezone'),
        ('Region', 'region'),
        ('City', 'city')
    ]

    for label, key in fields:
        val = data.get(key)
        if val is not None:
            print(f"{label:<50} {val}")
            
    print("-" * 70)
