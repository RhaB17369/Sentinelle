"""
URLScan.io Collector
Collects website analysis and screenshots
"""

import os
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import requests
import time


class URLScanCollector:
    """Collect website intelligence from URLScan.io"""
    
    BASE_URL = "https://urlscan.io/api/v1"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize URLScan collector.
        
        Args:
            api_key: URLScan API key (optional for searches)
        """
        self.logger = logging.getLogger(__name__)
        self.api_key = api_key or os.getenv('URLSCAN_API_KEY')
    
    def _make_request(self, endpoint: str, method: str = 'GET', data: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
        """Make API request to URLScan"""
        headers = {}
        if self.api_key:
            headers['API-Key'] = self.api_key
        
        try:
            if method == 'GET':
                response = requests.get(
                    f"{self.BASE_URL}/{endpoint}",
                    headers=headers,
                    timeout=10
                )
            else:
                response = requests.post(
                    f"{self.BASE_URL}/{endpoint}",
                    headers=headers,
                    json=data,
                    timeout=10
                )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                self.logger.debug(f"Resource not found: {endpoint}")
                return None
            else:
                self.logger.error(f"URLScan API error: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"URLScan request failed: {e}")
            return None
    
    def collect(self, url: str, wait_for_scan: bool = False) -> Dict[str, Any]:
        """
        Collect intelligence on a URL.
        
        Args:
            url: URL to analyze
            wait_for_scan: If True, submit new scan and wait for results
            
        Returns:
            Dictionary with URLScan intelligence
        """
        intelligence = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'source': 'urlscan',
            'scan_results': None,
            'screenshot': None,
            'verdict': None,
        }
        
        # Search for existing scans
        search_results = self._make_request(f"search/?q=page.url:{url}")
        
        if search_results and 'results' in search_results and search_results['results']:
            # Use most recent scan
            latest = search_results['results'][0]
            scan_id = latest.get('_id')
            
            # Get detailed results
            details = self._make_request(f"result/{scan_id}")
            
            if details:
                intelligence['scan_results'] = self._parse_scan_results(details)
                intelligence['screenshot'] = details.get('task', {}).get('screenshotURL')
                intelligence['verdict'] = self._parse_verdict(details)
                
                self.logger.info(f"URLScan data collected for {url}")
        
        elif wait_for_scan and self.api_key:
            # Submit new scan
            self.logger.info(f"Submitting new scan for {url}")
            scan = self._submit_scan(url)
            
            if scan:
                intelligence['scan_results'] = scan
        
        return intelligence
    
    def _submit_scan(self, url: str) -> Optional[Dict[str, Any]]:
        """Submit new URL scan"""
        if not self.api_key:
            self.logger.warning("API key required to submit scans")
            return None
        
        data = {
            'url': url,
            'visibility': 'public'
        }
        
        response = self._make_request('scan/', method='POST', data=data)
        
        if response and 'uuid' in response:
            scan_id = response['uuid']
            
            # Wait for scan to complete (max 30 seconds)
            for _ in range(30):
                time.sleep(1)
                
                result = self._make_request(f"result/{scan_id}")
                if result:
                    return self._parse_scan_results(result)
            
            self.logger.warning(f"Scan timeout for {url}")
        
        return None
    
    def _parse_scan_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse scan results"""
        page = data.get('page', {})
        stats = data.get('stats', {})
        
        return {
            'domain': page.get('domain'),
            'ip': page.get('ip'),
            'country': page.get('country'),
            'server': page.get('server'),
            'title': page.get('title'),
            'status': page.get('status'),
            'stats': {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'total_links': stats.get('totalLinks', 0),
                'unique_ips': stats.get('uniqIPs', 0),
                'unique_countries': stats.get('uniqCountries', 0),
            },
            'technologies': data.get('meta', {}).get('processors', {}).get('wappa', {}).get('data', []),
        }
    
    def _parse_verdict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse verdict from scan"""
        verdicts = data.get('verdicts', {})
        
        overall = verdicts.get('overall', {})
        
        return {
            'score': overall.get('score', 0),
            'malicious': overall.get('malicious', False),
            'categories': overall.get('categories', []),
            'brands': overall.get('brands', []),
            'tags': overall.get('tags', []),
        }
