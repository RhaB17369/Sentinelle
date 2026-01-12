"""
Vulnerability Scanner
Detects known vulnerabilities based on service versions
"""

import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime


class VulnerabilityScanner:
    """
    Scan for known vulnerabilities based on service versions.
    
    Uses simplified CVE matching (in production, use NVD database)
    """
    
    # Simplified vulnerability database (in production, use NVD JSON feeds)
    KNOWN_VULNS = {
        'OpenSSH': {
            '7.4': ['CVE-2018-15473', 'CVE-2018-15919'],
            '7.7': ['CVE-2019-6109', 'CVE-2019-6111'],
            '8.2': ['CVE-2020-15778'],
        },
        'Apache': {
            '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
            '2.4.50': ['CVE-2021-44224', 'CVE-2021-44790'],
        },
        'nginx': {
            '1.18.0': ['CVE-2021-23017'],
        },
    }
    
    def __init__(self):
        """Initialize vulnerability scanner"""
        self.logger = logging.getLogger(__name__)
    
    def scan_service(
        self,
        service: str,
        version: Optional[str],
        product: Optional[str]
    ) -> Dict[str, Any]:
        """
        Scan a service for known vulnerabilities.
        
        Args:
            service: Service name (e.g., 'ssh', 'http')
            version: Service version
            product: Product name (e.g., 'OpenSSH', 'Apache')
            
        Returns:
            Vulnerability scan results
        """
        result = {
            'service': service,
            'product': product,
            'version': version,
            'vulnerabilities': [],
            'risk_level': 'unknown',
        }
        
        if not product or not version:
            return result
        
        # Check known vulnerabilities
        if product in self.KNOWN_VULNS:
            if version in self.KNOWN_VULNS[product]:
                cves = self.KNOWN_VULNS[product][version]
                
                for cve in cves:
                    result['vulnerabilities'].append({
                        'cve_id': cve,
                        'severity': self._get_severity(cve),
                        'description': f'Known vulnerability in {product} {version}',
                    })
        
        # Determine risk level
        if result['vulnerabilities']:
            severities = [v['severity'] for v in result['vulnerabilities']]
            if 'critical' in severities:
                result['risk_level'] = 'critical'
            elif 'high' in severities:
                result['risk_level'] = 'high'
            elif 'medium' in severities:
                result['risk_level'] = 'medium'
            else:
                result['risk_level'] = 'low'
        else:
            result['risk_level'] = 'none'
        
        return result
    
    def scan_host(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan all services on a host for vulnerabilities.
        
        Args:
            scan_results: Results from network scanner
            
        Returns:
            Vulnerability scan results for all services
        """
        vuln_results = {
            'host': scan_results['host'],
            'timestamp': datetime.now().isoformat(),
            'total_services': len(scan_results.get('open_ports', [])),
            'vulnerable_services': [],
            'overall_risk': 'none',
        }
        
        for port_info in scan_results.get('open_ports', []):
            service = port_info.get('service')
            version = port_info.get('version')
            product = port_info.get('product')
            
            if service and (version or product):
                vuln_scan = self.scan_service(service, version, product)
                
                if vuln_scan['vulnerabilities']:
                    vuln_scan['port'] = port_info['port']
                    vuln_results['vulnerable_services'].append(vuln_scan)
        
        # Determine overall risk
        if vuln_results['vulnerable_services']:
            risk_levels = [s['risk_level'] for s in vuln_results['vulnerable_services']]
            if 'critical' in risk_levels:
                vuln_results['overall_risk'] = 'critical'
            elif 'high' in risk_levels:
                vuln_results['overall_risk'] = 'high'
            elif 'medium' in risk_levels:
                vuln_results['overall_risk'] = 'medium'
            else:
                vuln_results['overall_risk'] = 'low'
        
        self.logger.info(
            f"Vulnerability scan complete: {len(vuln_results['vulnerable_services'])} "
            f"vulnerable services found (risk: {vuln_results['overall_risk']})"
        )
        
        return vuln_results
    
    def _get_severity(self, cve_id: str) -> str:
        """Get severity for CVE (simplified)"""
        # In production, query NVD database
        # This is a simplified placeholder
        if '2021' in cve_id:
            return 'high'
        elif '2020' in cve_id:
            return 'medium'
        else:
            return 'low'
