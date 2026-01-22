"""
Domain/website OSINT engine.
Gathers intelligence from WHOIS, DNS, SSL certificates, and HTTP headers.
"""

import asyncio
import ssl
import socket
import logging
import httpx
import whois
import dns.asyncresolver
from typing import Dict, List, Optional, Any
from datetime import datetime

from ...core.engine import BaseEngine, EventType

__version__ = "1.0.0"

class DomainEngine(BaseEngine):
    """Refactored Domain Intelligence Engine."""
    
    def __init__(self, timeout: int = 10):
        super().__init__()
        self.timeout = timeout
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def run(self, domain: str, **kwargs) -> Dict[str, Any]:
        self.log(f"🔍 Starting deep analysis for domain: {domain}")
        self.progress(advance=0, total=5, description="Initializing")

        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat()
        }

        # 1. WHOIS (Sync, but wrapped in thread)
        try:
            self.progress(advance=1, description="Querying WHOIS")
            results["whois"] = await self._run_whois(domain)
            if results["whois"]:
                self.emit(EventType.DATA, data={"Category": "WHOIS", "Property": "Registrar", "Value": results["whois"].get("registrar")})
                self.emit(EventType.DATA, data={"Category": "WHOIS", "Property": "Organization", "Value": results["whois"].get("org")})
        except Exception as e:
            self.error(f"WHOIS block failed: {str(e)}")

        # 2. DNS
        try:
            self.progress(advance=1, description="Resolving DNS records")
            results["dns"] = await self._run_dns(domain)
            for record_type, values in results["dns"].items():
                if values:
                    self.emit(EventType.DATA, data={"Category": "DNS", "Property": record_type, "Value": ", ".join(values[:3]) + ("..." if len(values) > 3 else "")})
        except Exception as e:
            self.error(f"DNS block failed: {str(e)}")

        # 3. SSL
        try:
            self.progress(advance=1, description="Checking SSL/TLS")
            results["ssl"] = await self._run_ssl(domain)
            if results["ssl"]:
                self.emit(EventType.DATA, data={"Category": "Security", "Property": "Issuer", "Value": results["ssl"].get("issuer", {}).get("commonName")})
                self.emit(EventType.DATA, data={"Category": "Security", "Property": "Expires", "Value": results["ssl"].get("not_after")})
        except Exception as e:
            self.error(f"SSL block failed: {str(e)}")

        # 4. HTTP Headers & Tech
        try:
            self.progress(advance=1, description="Analyzing HTTP headers")
            results["http"] = await self._run_http(domain)
            if results["http"]:
                self.emit(EventType.DATA, data={"Category": "Network", "Property": "Server", "Value": results["http"].get("server")})
                self.emit(EventType.DATA, data={"Category": "Network", "Property": "Status", "Value": str(results["http"].get("status_code"))})
        except Exception as e:
            self.error(f"HTTP block failed: {str(e)}")

        self.progress(advance=1, description="Analysis complete")
        self.emit(EventType.COMPLETE, data=results)
        return results

    async def _run_whois(self, domain: str) -> Optional[Dict[str, Any]]:
        try:
            # whois.whois is blocking, run in executor
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, domain)
            
            return {
                'registrar': getattr(w, 'registrar', None),
                'creation_date': str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date),
                'expiration_date': str(w.expiration_date[0]) if isinstance(w.expiration_date, list) else str(w.expiration_date),
                'name_servers': w.name_servers if hasattr(w, 'name_servers') else None,
                'org': w.org if hasattr(w, 'org') else None,
                'country': w.country if hasattr(w, 'country') else None,
            }
        except Exception as e:
            self.log(f"⚠️ WHOIS failed: {str(e)}")
            return None

    async def _run_dns(self, domain: str) -> Dict[str, List[str]]:
        dns_data = {}
        record_types = ['A', 'MX', 'NS', 'TXT']
        
        for record_type in record_types:
            try:
                answers = await self.resolver.resolve(domain, record_type)
                dns_data[record_type] = [str(rdata) for rdata in answers]
            except Exception:
                dns_data[record_type] = []
        
        return dns_data

    async def _run_ssl(self, domain: str) -> Optional[Dict[str, Any]]:
        try:
            loop = asyncio.get_event_loop()
            context = ssl.create_default_context()
            
            # Use asyncio for connection to avoid blocking
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, 443, ssl=context, server_hostname=domain),
                timeout=self.timeout
            )
            
            cert = writer.get_extra_info('peercert')
            writer.close()
            await writer.wait_closed()
            
            if cert:
                return {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'not_after': cert.get('notAfter'),
                }
        except Exception:
            return None

    async def _run_http(self, domain: str) -> Optional[Dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(f"https://{domain}")
                return {
                    'status_code': response.status_code,
                    'server': response.headers.get('server'),
                    'powered_by': response.headers.get('x-powered-by'),
                }
        except Exception:
            return None
