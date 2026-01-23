
import httpx
import json
import logging
import asyncio
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod

from ...core.engine import BaseEngine, EventType

logger = logging.getLogger(__name__)

__version__ = "2.0.0"

class GeolocationProvider(ABC):
    """Abstract base class for geolocation data providers."""
    @abstractmethod
    async def get_data(self, ip: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        pass

class IPAPIProvider(GeolocationProvider):
    """Provider for ip-api.com."""
    URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,as,query"

    async def get_data(self, ip: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        try:
            response = await client.get(self.URL.format(ip=ip), timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'asn': data.get('as'),
                    }
            return None
        except Exception as e:
            logger.debug(f"ip-api.com lookup failed for {ip}: {e}")
            return None

class GeoJSProvider(GeolocationProvider):
    """Provider for get.geojs.io."""
    URL = "https://get.geojs.io/v1/ip/geo/{ip}.json"

    async def get_data(self, ip: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        try:
            response = await client.get(self.URL.format(ip=ip), timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country'),
                    'country_code': data.get('country_code'),
                    'region': data.get('region'),
                    'city': data.get('city'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'timezone': data.get('timezone'),
                    'isp': data.get('organization_name'),
                    'asn': data.get('asn'),
                }
            return None
        except Exception as e:
            logger.debug(f"GeoJS lookup failed for {ip}: {e}")
            return None

class IPEngine(BaseEngine):
    """
    Advanced Engine for IP Intelligence gathering following SOLID principles.
    """
    
    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        super().__init__()
        self._client = client
        self._loop = None
        self.providers: List[GeolocationProvider] = [
            IPAPIProvider(),
            GeoJSProvider()
        ]

    async def _get_client(self) -> httpx.AsyncClient:
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if self._client is None or self._client.is_closed or self._loop != current_loop:
            # Note: We don't close the old client here to avoid issues with other tasks
            # but in this CLI context it's generally fine.
            self._client = httpx.AsyncClient(timeout=10, follow_redirects=True)
            self._loop = current_loop
        return self._client

    async def get_my_ip(self) -> Optional[str]:
        """Get public IP of the caller."""
        try:
            client = await self._get_client()
            response = await client.get("https://get.geojs.io/v1/ip.json")
            if response.status_code == 200:
                return response.json().get('ip')
            return None
        except Exception as e:
            logger.warning("Failed to get public IP: %s", e)
            return None

    async def run(self, ip_address: str, **kwargs) -> Optional[Dict[str, Any]]:
        self.log(f"🔍 Starting Intelligence gathering for IP: {ip_address}")
        self.progress(advance=0, total=len(self.providers) + 1, description="Initializing")
        
        final_data = {}
        client = await self._get_client()
        
        for provider in self.providers:
            provider_name = provider.__class__.__name__
            self.progress(advance=1, description=f"Querying {provider_name}")
            
            data = await provider.get_data(ip_address, client)
            if data:
                # Fill missing data
                for key, value in data.items():
                    if value and not final_data.get(key):
                        final_data[key] = value
                        self.emit(EventType.DATA, data={"Category": "Intelligence", "Property": key.replace('_', ' ').capitalize(), "Value": str(value)})
                
                # If we have all critical data, we can stop early
                if all(final_data.get(k) for k in ['latitude', 'longitude', 'isp']):
                    break

        # DNS PTR record as additional info
        self.progress(advance=1, description="Fetching PTR record")
        try:
            ptr_resp = await client.get(f"https://get.geojs.io/v1/dns/ptr/{ip_address}.json")
            if ptr_resp.status_code == 200:
                ptr = ptr_resp.json().get('ptr')
                if ptr and "Failed" not in str(ptr):
                    final_data['ptr'] = ptr
                    self.emit(EventType.DATA, data={"Category": "Network", "Property": "PTR", "Value": ptr})
        except:
            pass

        self.progress(advance=1, description="Analysis complete")
        self.emit(EventType.COMPLETE, data=final_data)
        return final_data

# Backward compatibility layer
_engine = IPEngine()

async def getIP() -> Optional[str]:
    return await _engine.get_my_ip()

async def getGeoData(ip: str) -> Optional[Dict[str, Any]]:
    return await _engine.run(ip)

async def getCountry(ip: str, output_format: str = 'plain') -> Any:
    data = await _engine.run(ip) or {}
    country = data.get('country', 'Unknown')
    if output_format == 'json':
        return json.dumps({'country': country, 'country_code': data.get('country_code')})
    return country

async def getPTR(ip: str) -> Optional[str]:
    data = await _engine.run(ip)
    return data.get('ptr')

def _sync_run(coro):
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    if loop.is_running():
        import threading
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(lambda: asyncio.run(coro)).result()
    else:
        return loop.run_until_complete(coro)

def showIpDetails(ip: str):
    """
    Professional display of IP intelligence details.
    """
    data = _sync_run(_engine.run(ip))
    if not data:
        print(f"[-] No data found for {ip}")
        return

    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        console = Console()

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Property", style="bold cyan", width=20)
        table.add_column("Value", style="white")

        # Required fields display
        display_map = [
            ('Country', 'country'),
            ('Country Code', 'country_code'),
            ('Region', 'region'),
            ('City', 'city'),
            ('Latitude', 'latitude'),
            ('Longitude', 'longitude'),
            ('Timezone', 'timezone'),
            ('ISP/Operator', 'isp'),
            ('ASN', 'asn'),
            ('PTR Record', 'ptr')
        ]

        found_any = False
        for label, key in display_map:
            val = data.get(key)
            if val:
                table.add_row(f"{label}:", str(val))
                found_any = True

        if not found_any:
            table.add_row("Status:", "No specific intelligence found.")

        console.print(Panel(table, title=f"[bold green]IP Intelligence: {ip}[/]", expand=False))
        
        if data.get('latitude') and data.get('longitude'):
            console.print(f"\n[bold yellow]📍 Real-time GPS Coordinates:[/] {data['latitude']}, {data['longitude']}")
            console.print(f"[dim italic]Google Maps: https://www.google.com/maps?q={data['latitude']},{data['longitude']}[/]")

    except ImportError:
        print(f"\n{'='*20} IP INTELLIGENCE: {ip} {'='*20}")
        for key, val in data.items():
            print(f"{key.replace('_', ' ').capitalize():<20}: {val}")

def showCountryDetails(ip: str):
    data = _sync_run(_engine.run(ip))
    if data:
        print(f"Country: {data.get('country')} ({data.get('country_code')})")
        print(f"Region: {data.get('region')}")
        print(f"City: {data.get('city')}")
