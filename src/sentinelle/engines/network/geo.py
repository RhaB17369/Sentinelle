
import httpx
import json
import logging
import asyncio
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


from ...core.engine import BaseEngine, EventType

__version__ = "1.0.0"

class IPEngine(BaseEngine):
    """
    Unified Engine for IP Intelligence gathering.
    """
    BASE_URL = "https://get.geojs.io/v1/ip/geo/{ip}.json"
    PTR_URL = "https://get.geojs.io/v1/dns/ptr/{ip}.json"
    IP_URL = "https://get.geojs.io/v1/ip.json"

    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        super().__init__()
        self.client = client

    async def _get_client(self) -> httpx.AsyncClient:
        if self.client is None or self.client.is_closed:
            self.client = httpx.AsyncClient(timeout=10, follow_redirects=True)
        return self.client

    async def get_my_ip(self) -> Optional[str]:
        """Get public IP of the caller."""
        try:
            client = await self._get_client()
            response = await client.get(self.IP_URL)
            if response.status_code == 200:
                return response.json().get('ip')
            return None
        except Exception as e:
            logger.warning("Failed to get public IP: %s", e)
            return None

    async def get_geo_data(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get all available geodata for a specific IP address from GeoJS."""
        try:
            client = await self._get_client()
            url = self.BASE_URL.format(ip=ip_address)
            response = await client.get(url)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.warning("GeoJS geo lookup failed for %s: %s", ip_address, e)
            return None

    async def get_ptr_data(self, ip_address: str) -> Optional[str]:
        """Get the DNS PTR record of an IP address via GeoJS."""
        try:
            client = await self._get_client()
            url = self.PTR_URL.format(ip=ip_address)
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                return data.get('ptr')
            return None
        except Exception as e:
            logger.debug("GeoJS PTR lookup failed for %s: %s", ip_address, e)
            return None

    async def run(self, ip_address: str, **kwargs) -> Optional[Dict[str, Any]]:
        self.log(f"🔍 Analyzing IP: {ip_address}...")
        self.progress(advance=0, total=4, description="Initializing")
        
        geo_data = {}
        client = await self._get_client()
        
        # 1. Try ip-api.com - Primary
        self.progress(advance=1, description="Querying primary database")
        try:
            response = await client.get(f"https://demo.ip-api.com/json/{ip_address}?fields=66846719", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    geo_data.update({
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'asn': data.get('as'),
                    })
                    # Emit individual attributes as data events for real-time table updates
                    for k, v in geo_data.items():
                        if v: self.emit(EventType.DATA, data={"Category": "Basic", "Property": k.capitalize(), "Value": str(v)})
        except Exception as e:
            self.log(f"⚠️ Primary lookup failed: {e}")

        # 2. Try GeoJS for fallback
        self.progress(advance=1, description="Querying fallback database")
        try:
            url = self.BASE_URL.format(ip=ip_address)
            response = await client.get(url)
            if response.status_code == 200:
                raw_data = response.json()
                mapping = {
                    'country': 'country',
                    'country_code': 'country_code',
                    'region': 'region',
                    'city': 'city',
                    'latitude': 'latitude',
                    'longitude': 'longitude',
                    'timezone': 'timezone',
                    'isp': 'organization_name',
                    'asn': 'asn',
                    'organization': 'organization'
                }
                for k, v in mapping.items():
                    if not geo_data.get(k) and raw_data.get(v):
                        val = raw_data.get(v)
                        geo_data[k] = val
                        self.emit(EventType.DATA, data={"Category": "Geo", "Property": k.capitalize(), "Value": str(val)})
        except Exception as e:
            self.log(f"⚠️ Fallback lookup failed: {e}")

        # 3. DNS PTR
        self.progress(advance=1, description="Checking DNS records")
        try:
            url = self.PTR_URL.format(ip=ip_address)
            response = await client.get(url)
            if response.status_code == 200:
                ptr = response.json().get('ptr')
                if ptr:
                    geo_data['ptr'] = ptr
                    self.emit(EventType.DATA, data={"Category": "Network", "Property": "PTR", "Value": ptr})
        except: pass

        self.progress(advance=1, description="Analysis complete")
        self.emit(EventType.COMPLETE, data=geo_data)
        return geo_data

class GeoJSCollector(IPEngine):
    """Legacy compatibility class."""
    async def collect_enriched(self, ip_address: str) -> Optional[Dict[str, Any]]:
        return await self.run(ip_address)


# Standalone functions for backward compatibility or direct use (now async)

_collector = GeoJSCollector()


async def getIP() -> Optional[str]:
    """Get the current public IP address (Async)."""
    return await _collector.get_my_ip()


async def getGeoData(ip: str) -> Optional[Dict[str, Any]]:
    """Get geodata for a specific IP (Async)."""
    return await _collector.get_geo_data(ip)


async def getCountry(ip: str, output_format: str = 'plain') -> Any:
    """Get country information for an IP (Async)."""
    data = await _collector.get_geo_data(ip) or {}
    country = data.get('country', 'Unknown')
    code = data.get('country_code', '??')

    if output_format == 'json':
        return json.dumps({'country': country, 'country_code': code})
    return country


async def getPTR(ip: str) -> Optional[str]:
    """Get PTR record for an IP (Async)."""
    return await _collector.get_ptr_data(ip)


def _sync_run(coro):
    """Helper to run a coroutine synchronously from a non-async context."""
    try:
        return asyncio.run(coro)
    except RuntimeError:
        # Loop already running, try to use a new loop in a thread or fail
        new_loop = asyncio.new_event_loop()
        try:
            return new_loop.run_until_complete(coro)
        finally:
            new_loop.close()


def showIpDetails(ip: str, verbosity: str = 'brief', include_latency: bool = False, collector=None):
    """Synchronous wrapper for printing summary."""
    if collector is None:
        collector = _collector
    
    geo = _sync_run(collector.collect_enriched(ip))
        
    if not geo:
        print(f"No intelligence gathered for IP: {ip}")
        return

    try:
        from rich.console import Console
        from rich.table import Table
        console = Console()

        table = Table(show_header=False, show_lines=False)
        table.add_column('Field', width=24)
        table.add_column('Value')

        table.add_row('IP', ip)
        if geo.get('country'):
            table.add_row('Country', f"[cyan]{geo['country']}[/]")
        if geo.get('region'):
            table.add_row('Region', geo['region'])
        if geo.get('city'):
            table.add_row('City', geo['city'])
        if geo.get('isp'):
            table.add_row('ISP', f"[yellow]{geo['isp']}[/]")
        if geo.get('asn'):
            table.add_row('ASN', str(geo['asn']))
        if geo.get('ptr'):
            table.add_row('PTR', geo['ptr'])
        if geo.get('latitude') and geo.get('longitude'):
            table.add_row('Coordinates', f"{geo['latitude']}, {geo['longitude']}")

        console.rule("IP INTELLIGENCE SUMMARY")
        console.print(table)
    except Exception:
        print(f"IP: {ip}")
        print(f"Country: {geo.get('country')}")
        print(f"ISP: {geo.get('isp')}")

def showCountryDetails(ip: str):
    """Print detailed Country information."""
    data = _sync_run(_collector.get_geo_data(ip))
    if data:
        print(f"Country: {data.get('country')}")
        print(f"Code: {data.get('country_code')}")
