"""
Network Scanner - Port Scanner and Service Detection
High-performance network reconnaissance (LEGAL USE ONLY)
"""

import socket
import struct
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import concurrent.futures
import time


class PortScanner:
    """
    TCP Port Scanner (Connect Scan - No root required)
    
    WARNING: Only scan networks you own or have explicit permission to scan.
    Unauthorized scanning is ILLEGAL in most jurisdictions.
    """
    
    # Common ports to scan
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443, 8888
    ]
    
    def __init__(self, timeout: float = 1.0, max_workers: int = 100):
        """
        Initialize port scanner.
        
        Args:
            timeout: Connection timeout in seconds
            max_workers: Maximum concurrent scans
        """
        self.logger = logging.getLogger(__name__)
        self.timeout = timeout
        self.max_workers = max_workers
        
        self.logger.warning(
            "⚠️  PORT SCANNING WARNING ⚠️\n"
            "Only scan networks you own or have explicit written permission to scan.\n"
            "Unauthorized scanning is ILLEGAL and may result in criminal prosecution."
        )
    
    def scan_port(self, host: str, port: int) -> Dict[str, Any]:
        """
        Scan a single port using TCP connect.
        
        Args:
            host: Target host (IP or hostname)
            port: Port number
            
        Returns:
            Dictionary with scan result
        """
        result = {
            'port': port,
            'state': 'closed',
            'service': self._get_service_name(port),
            'banner': None,
        }
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Try to connect
            start_time = time.time()
            connection_result = sock.connect_ex((host, port))
            latency = time.time() - start_time
            
            if connection_result == 0:
                result['state'] = 'open'
                result['latency'] = round(latency * 1000, 2)  # ms
                
                # Try to grab banner
                try:
                    sock.send(b'\r\n')
                    banner = sock.recv(1024)
                    if banner:
                        result['banner'] = banner.decode('utf-8', errors='ignore').strip()
                except:
                    pass
            
            sock.close()
            
        except socket.timeout:
            result['state'] = 'filtered'
        except Exception as e:
            self.logger.debug(f"Error scanning {host}:{port}: {e}")
            result['state'] = 'error'
            result['error'] = str(e)
        
        return result
    
    def scan_ports(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        scan_common: bool = True
    ) -> Dict[str, Any]:
        """
        Scan multiple ports on a host.
        
        Args:
            host: Target host
            ports: List of ports to scan (None = common ports)
            scan_common: If True and ports is None, scan common ports
            
        Returns:
            Dictionary with scan results
        """
        if ports is None:
            if scan_common:
                ports = self.COMMON_PORTS
            else:
                ports = list(range(1, 1025))  # Well-known ports
        
        self.logger.info(f"Scanning {len(ports)} ports on {host}")
        
        scan_results = {
            'host': host,
            'timestamp': datetime.now().isoformat(),
            'total_ports': len(ports),
            'open_ports': [],
            'filtered_ports': [],
            'scan_duration': 0,
        }
        
        start_time = time.time()
        
        # Parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self.scan_port, host, port): port
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                
                if result['state'] == 'open':
                    scan_results['open_ports'].append(result)
                elif result['state'] == 'filtered':
                    scan_results['filtered_ports'].append(result['port'])
        
        scan_results['scan_duration'] = round(time.time() - start_time, 2)
        
        self.logger.info(
            f"Scan complete: {len(scan_results['open_ports'])} open, "
            f"{len(scan_results['filtered_ports'])} filtered"
        )
        
        return scan_results
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        try:
            return socket.getservbyport(port)
        except:
            # Common services not in socket database
            services = {
                8080: 'http-proxy',
                8443: 'https-alt',
                8888: 'http-alt',
                3389: 'ms-wbt-server',
                5900: 'vnc',
            }
            return services.get(port, 'unknown')


class ServiceDetector:
    """Detect services running on open ports"""
    
    # Service signatures (simplified)
    SIGNATURES = {
        'SSH': [b'SSH-', b'OpenSSH'],
        'HTTP': [b'HTTP/', b'Server:'],
        'FTP': [b'220', b'FTP'],
        'SMTP': [b'220', b'SMTP', b'ESMTP'],
        'MySQL': [b'mysql', b'\x00\x00\x00\x0a'],
        'PostgreSQL': [b'FATAL', b'database'],
        'Redis': [b'PONG', b'redis_version'],
        'MongoDB': [b'MongoDB', b'ismaster'],
    }
    
    def __init__(self, timeout: float = 2.0):
        """
        Initialize service detector.
        
        Args:
            timeout: Detection timeout
        """
        self.logger = logging.getLogger(__name__)
        self.timeout = timeout
    
    def detect_service(self, host: str, port: int, banner: Optional[str] = None) -> Dict[str, Any]:
        """
        Detect service on a port.
        
        Args:
            host: Target host
            port: Port number
            banner: Optional banner from port scan
            
        Returns:
            Service detection results
        """
        result = {
            'port': port,
            'service': 'unknown',
            'version': None,
            'product': None,
            'banner': banner,
        }
        
        # If we have a banner, analyze it
        if banner:
            result.update(self._analyze_banner(banner))
            return result
        
        # Otherwise, try to grab banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Send probe
            sock.send(b'\r\n')
            response = sock.recv(4096)
            
            if response:
                banner_str = response.decode('utf-8', errors='ignore')
                result['banner'] = banner_str
                result.update(self._analyze_banner(banner_str))
            
            sock.close()
            
        except Exception as e:
            self.logger.debug(f"Service detection failed for {host}:{port}: {e}")
        
        return result
    
    def _analyze_banner(self, banner: str) -> Dict[str, Any]:
        """Analyze banner to identify service"""
        banner_bytes = banner.encode('utf-8', errors='ignore')
        
        for service, signatures in self.SIGNATURES.items():
            for sig in signatures:
                if sig in banner_bytes:
                    return {
                        'service': service.lower(),
                        'product': self._extract_product(banner, service),
                        'version': self._extract_version(banner),
                    }
        
        return {'service': 'unknown'}
    
    def _extract_product(self, banner: str, service: str) -> Optional[str]:
        """Extract product name from banner"""
        # Simplified extraction
        if 'OpenSSH' in banner:
            return 'OpenSSH'
        elif 'Apache' in banner:
            return 'Apache'
        elif 'nginx' in banner:
            return 'nginx'
        elif 'Microsoft' in banner:
            return 'Microsoft IIS'
        
        return None
    
    def _extract_version(self, banner: str) -> Optional[str]:
        """Extract version from banner"""
        import re
        
        # Look for version patterns like "1.2.3" or "v1.2"
        version_pattern = r'(?:version\s+)?v?(\d+\.\d+(?:\.\d+)?)'
        match = re.search(version_pattern, banner, re.IGNORECASE)
        
        if match:
            return match.group(1)
        
        return None


class NetworkScanner:
    """
    Complete network scanner combining port scanning and service detection.
    
    LEGAL WARNING: Only use on networks you own or have permission to scan.
    """
    
    def __init__(self):
        """Initialize network scanner"""
        self.logger = logging.getLogger(__name__)
        self.port_scanner = PortScanner()
        self.service_detector = ServiceDetector()
    
    def scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        detect_services: bool = True
    ) -> Dict[str, Any]:
        """
        Perform complete network scan.
        
        Args:
            target: Target host or IP
            ports: Ports to scan (None = common ports)
            detect_services: Enable service detection
            
        Returns:
            Complete scan results
        """
        self.logger.info(f"Starting network scan of {target}")
        
        # Port scan
        port_results = self.port_scanner.scan_ports(target, ports)
        
        # Service detection on open ports
        if detect_services and port_results['open_ports']:
            self.logger.info(f"Detecting services on {len(port_results['open_ports'])} open ports")
            
            for port_info in port_results['open_ports']:
                service_info = self.service_detector.detect_service(
                    target,
                    port_info['port'],
                    port_info.get('banner')
                )
                port_info.update(service_info)
        
        return port_results
