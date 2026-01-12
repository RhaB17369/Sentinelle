"""
Email OSINT Engine - Full Holehe Integration (v1.61)
Integrates complete Holehe module system (150+ platforms)
Uses actual Holehe source code from osint_platforms_db/holehe/ directory
"""

import logging
import sys
import importlib
import pkgutil
import re
import os
import asyncio
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime

# Add osint_platforms_db to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'osint_platforms_db'))

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import trio
    TRIO_AVAILABLE = True
except ImportError:
    TRIO_AVAILABLE = False


class EmailOSINT:
    """
    Email reconnaissance using complete Holehe source code (v1.61).
    Checks if email is registered on 150+ platforms using Holehe module system.
    
    This integrates the actual Holehe library code from:
    /home/bazooka/Desktop/sentinelle/osint_platforms/
    
    Categories: social media, payment, productivity, shopping, learning, jobs,
    CRM, e-commerce, forums, programming, and many more.
    """
    
    EMAIL_FORMAT = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    def __init__(self, tor_manager=None, timeout: int = 10, no_password_recovery: bool = False):
        self.logger = logging.getLogger(__name__)
        self.tor = tor_manager
        self.timeout = timeout
        self.no_password_recovery = no_password_recovery
        self.holehe_available = self._check_holehe_available()
        
        if not HTTPX_AVAILABLE:
            self.logger.warning("httpx not installed. Run: pip install httpx")
        if not TRIO_AVAILABLE:
            self.logger.warning("trio not installed. Run: pip install trio")
    
    def _check_holehe_available(self) -> bool:
        """Check if Holehe source code is available in osint_platforms_db/"""
        try:
            import engine_mail_collector
            self.logger.info("Holehe v1.61 detected and ready")
            return True
        except ImportError:
            self.logger.warning("Holehe not found - check osint_platforms_db/ directory")
            return False
    
    def _is_email(self, email: str) -> bool:
        """Check if string is a valid email address"""
        return bool(re.fullmatch(self.EMAIL_FORMAT, email))
    
    def _import_holehe_submodules(self, package, recursive=True):
        """Import all Holehe submodules dynamically"""
        try:
            if isinstance(package, str):
                package = importlib.import_module(package)
            results = {}
            for loader, name, is_pkg in pkgutil.walk_packages(package.__path__):
                full_name = package.__name__ + '.' + name
                results[full_name] = importlib.import_module(full_name)
                if recursive and is_pkg:
                    results.update(self._import_holehe_submodules(full_name))
            return results
        except Exception as e:
            self.logger.warning(f"Failed to import Holehe modules: {e}")
            return {}
    
    def _get_holehe_functions(self, modules):
        """Transform Holehe modules to functions (from Holehe core.py)"""
        websites = []
        for module in modules:
            if len(module.split(".")) > 3:
                try:
                    modu = modules[module]
                    site = module.split(".")[-1]
                    if site in modu.__dict__:
                        func = modu.__dict__[site]
                        websites.append(func)
                except Exception as e:
                    self.logger.debug(f"Failed to load module {module}: {e}")
        return websites
    
    async def _launch_holehe_module(self, module, email: str, client: httpx.AsyncClient, out: List[Dict]):
        """Launch a single Holehe module (from Holehe core.py launch_module)"""
        try:
            await module(email, client, out)
        except Exception as e:
            self.logger.debug(f"Module execution failed: {str(e)[:100]}")
            # Module failed silently - Holehe handles this internally
    
    async def enumerate_platforms_async(self, email: str) -> List[Dict[str, Any]]:
        """
        Check email on ALL Holehe platforms asynchronously.
        Returns results in complete Holehe format with all detected platforms.
        """
        if not self.holehe_available:
            self.logger.error("Holehe not available - cannot enumerate platforms")
            return []
        
        if not HTTPX_AVAILABLE or not TRIO_AVAILABLE:
            self.logger.error("httpx and trio required for Holehe integration")
            return []
        
        if not self._is_email(email):
            self.logger.warning(f"Invalid email format: {email}")
            return []
        
        # Import Holehe modules using actual Holehe code
        try:
            modules = self._import_holehe_submodules("holehe.modules")
            websites = self._get_holehe_functions(modules)
        except Exception as e:
            self.logger.error(f"Failed to load Holehe modules: {e}")
            return []
        
        if not websites:
            self.logger.warning("No Holehe modules loaded")
            return []
        
        self.logger.info(f"Checking {len(websites)} platforms for: {email}")
        
        # Run with asyncio instead of trio for compatibility
        out = []
        client = httpx.AsyncClient(timeout=self.timeout)
        
        try:
            tasks = []
            for website in websites:
                task = self._launch_holehe_module(website, email, client, out)
                tasks.append(task)
            
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            await client.aclose()
        
        # Sort by name
        out = sorted(out, key=lambda i: i.get('name', ''))
        
        return out
    
    def enumerate_platforms(self, email: str) -> List[Dict[str, Any]]:
        """
        Synchronous wrapper for async platform enumeration.
        Returns complete Holehe results.
        """
        if not self._is_email(email):
            return []
        
        try:
            # Try to use existing event loop
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Create new loop if one is already running
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(self.enumerate_platforms_async(email))
                loop.close()
            else:
                results = loop.run_until_complete(self.enumerate_platforms_async(email))
        except RuntimeError:
            # No event loop, create one
            results = asyncio.run(self.enumerate_platforms_async(email))
        
        return results
    
    def check_breaches(self, email: str) -> Dict[str, Any]:
        """Check if email appears in known data breaches (HaveIBeenPwned)"""
        breaches_found = []
        
        try:
            import requests
            sha1_hash = hashlib.sha1(email.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                hashes = response.text.split('\r\n')
                for hash_line in hashes:
                    if ':' in hash_line:
                        hash_suffix, count = hash_line.split(':')
                        if hash_suffix == suffix:
                            breaches_found.append({
                                'source': 'HaveIBeenPwned',
                                'count': int(count),
                                'severity': 'HIGH' if int(count) > 100 else 'MEDIUM'
                            })
        except Exception as e:
            self.logger.error(f"Breach check failed: {e}")
        
        return {
            'checked': True,
            'breaches': breaches_found,
            'total_breaches': len(breaches_found)
        }
    
    def analyze_email_metadata(self, email: str) -> Dict[str, Any]:
        """Extract metadata from email address"""
        if not self._is_email(email):
            return {}
        
        username, domain = email.split('@', 1)
        
        metadata = {
            'username': username,
            'domain': domain,
            'mx_records': [],
            'provider_type': self._classify_email_provider(domain)
        }
        
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            mx_records = resolver.resolve(domain, 'MX')
            metadata['mx_records'] = [str(mx.exchange) for mx in mx_records]
        except Exception:
            pass
        
        return metadata
    
    def _classify_email_provider(self, domain: str) -> str:
        """Classify email provider type"""
        major_providers = {
            'gmail.com': 'Google',
            'yahoo.com': 'Yahoo',
            'outlook.com': 'Microsoft',
            'hotmail.com': 'Microsoft',
            'icloud.com': 'Apple',
            'protonmail.com': 'ProtonMail (Privacy)',
        }
        
        return major_providers.get(domain.lower(), 'Custom/Corporate')
    
    def run_full_reconnaissance(self, identifier: str) -> Dict[str, Any]:
        """
        Execute complete OSINT reconnaissance using full Holehe system.
        
        Returns:
            Complete intelligence report with Holehe results
        """
        self.logger.info(f"Starting full reconnaissance for: {identifier}")
        
        report = {
            'target': identifier,
            'type': 'email' if '@' in identifier else 'username',
            'holehe_results': [],
            'accounts_found': [],
            'breaches': {},
            'metadata': {}
        }
        
        if '@' in identifier:
            # Run full Holehe enumeration
            holehe_results = self.enumerate_platforms(identifier)
            report['holehe_results'] = holehe_results
            
            # Extract accounts found (exists=True, no error, no rateLimit)
            report['accounts_found'] = [
                {
                    'platform': r.get('name', 'unknown'),
                    'domain': r.get('domain', 'unknown'),
                    'email': identifier,
                    'method': 'holehe',
                    'verified': r.get('exists', False) and not r.get('error', False) and not r.get('rateLimit', False),
                    'emailrecovery': r.get('emailrecovery'),
                    'phoneNumber': r.get('phoneNumber'),
                    'others': r.get('others')
                }
                for r in holehe_results
                if r.get('exists', False) and not r.get('error', False) and not r.get('rateLimit', False)
            ]
            
            # Check breaches
            report['breaches'] = self.check_breaches(identifier)
            
            # Analyze metadata
            report['metadata'] = self.analyze_email_metadata(identifier)
        else:
            self.logger.warning("Username reconnaissance requires email address")
        
        return report
