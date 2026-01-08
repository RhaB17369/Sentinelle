"""
Encrypted Traffic Analyzer - TLS/SSL Analysis Without Decryption
JA3/JA3S fingerprinting and C2 detection
"""

import logging
import hashlib
from typing import Dict, List, Any, Optional
from collections import defaultdict
import re


class EncryptedTrafficAnalyzer:
    """
    Analyze encrypted traffic without decryption.
    
    Techniques:
    - JA3/JA3S fingerprinting
    - Packet size/timing analysis
    - C2 detection
    - Certificate analysis
    """
    
    # Known malware JA3 fingerprints
    MALWARE_JA3 = {
        'e7d705a3286e19ea42f587b344ee6865': 'Trickbot',
        'a0e9f5d64349fb13191bc781f81f42e1': 'Emotet',
        '6734f37431670b3ab4292b8f60f29984': 'Dridex',
        'ada70206e40642a3e4461f35503241d5': 'Cobalt Strike',
    }
    
    def __init__(self):
        """Initialize traffic analyzer"""
        self.logger = logging.getLogger(__name__)
    
    def calculate_ja3(self, tls_hello: Dict[str, Any]) -> str:
        """
        Calculate JA3 fingerprint from TLS Client Hello.
        
        Args:
            tls_hello: Dictionary with:
                - version: TLS version
                - ciphers: List of cipher suites
                - extensions: List of extensions
                - curves: List of elliptic curves
                - point_formats: List of EC point formats
                
        Returns:
            JA3 fingerprint (MD5 hash)
        """
        # JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        components = [
            str(tls_hello.get('version', '')),
            '-'.join(map(str, tls_hello.get('ciphers', []))),
            '-'.join(map(str, tls_hello.get('extensions', []))),
            '-'.join(map(str, tls_hello.get('curves', []))),
            '-'.join(map(str, tls_hello.get('point_formats', []))),
        ]
        
        ja3_string = ','.join(components)
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        
        return ja3_hash
    
    def calculate_ja3s(self, tls_server_hello: Dict[str, Any]) -> str:
        """
        Calculate JA3S fingerprint from TLS Server Hello.
        
        Args:
            tls_server_hello: Server hello parameters
            
        Returns:
            JA3S fingerprint (MD5 hash)
        """
        components = [
            str(tls_server_hello.get('version', '')),
            str(tls_server_hello.get('cipher', '')),
            '-'.join(map(str, tls_server_hello.get('extensions', []))),
        ]
        
        ja3s_string = ','.join(components)
        ja3s_hash = hashlib.md5(ja3s_string.encode()).hexdigest()
        
        return ja3s_hash
    
    def analyze_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze TLS session for threats.
        
        Args:
            session_data: Session information including:
                - client_hello: TLS client hello
                - server_hello: TLS server hello
                - packets: List of packet sizes/timings
                - certificate: Server certificate
                
        Returns:
            Analysis results
        """
        result = {
            'ja3': None,
            'ja3s': None,
            'threat_detected': False,
            'threat_type': None,
            'application': None,
            'anomalies': [],
        }
        
        # Calculate fingerprints
        if 'client_hello' in session_data:
            result['ja3'] = self.calculate_ja3(session_data['client_hello'])
            
            # Check against known malware
            if result['ja3'] in self.MALWARE_JA3:
                result['threat_detected'] = True
                result['threat_type'] = self.MALWARE_JA3[result['ja3']]
        
        if 'server_hello' in session_data:
            result['ja3s'] = self.calculate_ja3s(session_data['server_hello'])
        
        # Packet analysis
        if 'packets' in session_data:
            packet_analysis = self._analyze_packets(session_data['packets'])
            result.update(packet_analysis)
        
        # Certificate analysis
        if 'certificate' in session_data:
            cert_analysis = self._analyze_certificate(session_data['certificate'])
            result['certificate_analysis'] = cert_analysis
        
        return result
    
    def _analyze_packets(self, packets: List[Dict]) -> Dict[str, Any]:
        """Analyze packet patterns"""
        analysis = {
            'total_packets': len(packets),
            'avg_packet_size': 0,
            'packet_size_variance': 0,
            'timing_regularity': 0,
            'potential_c2': False,
        }
        
        if not packets:
            return analysis
        
        # Packet sizes
        sizes = [p.get('size', 0) for p in packets]
        if sizes:
            import numpy as np
            analysis['avg_packet_size'] = np.mean(sizes)
            analysis['packet_size_variance'] = np.var(sizes)
        
        # Timing analysis
        timestamps = [p.get('timestamp', 0) for p in packets]
        if len(timestamps) > 1:
            import numpy as np
            intervals = np.diff(timestamps)
            
            # Regular intervals suggest beaconing (C2)
            if len(intervals) > 5:
                interval_variance = np.var(intervals)
                interval_mean = np.mean(intervals)
                
                # Low variance = regular beaconing
                if interval_variance < (interval_mean * 0.1):
                    analysis['potential_c2'] = True
                    analysis['timing_regularity'] = 1.0 - (interval_variance / max(interval_mean, 1))
        
        return analysis
    
    def _analyze_certificate(self, certificate: Dict) -> Dict[str, Any]:
        """Analyze SSL certificate"""
        analysis = {
            'issuer': certificate.get('issuer'),
            'subject': certificate.get('subject'),
            'valid_from': certificate.get('valid_from'),
            'valid_to': certificate.get('valid_to'),
            'suspicious': False,
            'reasons': [],
        }
        
        # Self-signed check
        if certificate.get('issuer') == certificate.get('subject'):
            analysis['suspicious'] = True
            analysis['reasons'].append('self_signed')
        
        # Short validity period
        if 'valid_from' in certificate and 'valid_to' in certificate:
            from datetime import datetime
            try:
                valid_from = datetime.fromisoformat(certificate['valid_from'])
                valid_to = datetime.fromisoformat(certificate['valid_to'])
                validity_days = (valid_to - valid_from).days
                
                if validity_days < 30:
                    analysis['suspicious'] = True
                    analysis['reasons'].append(f'short_validity_{validity_days}days')
            except:
                pass
        
        return analysis
    
    def detect_c2_traffic(self, sessions: List[Dict]) -> List[Dict]:
        """
        Detect Command & Control traffic patterns.
        
        Args:
            sessions: List of TLS sessions
            
        Returns:
            List of suspicious sessions
        """
        suspicious = []
        
        for session in sessions:
            analysis = self.analyze_session(session)
            
            # C2 indicators
            if analysis.get('threat_detected'):
                suspicious.append({
                    'session': session,
                    'reason': 'known_malware_ja3',
                    'threat': analysis['threat_type'],
                })
            elif analysis.get('potential_c2'):
                suspicious.append({
                    'session': session,
                    'reason': 'beaconing_pattern',
                    'regularity': analysis.get('timing_regularity', 0),
                })
        
        return suspicious
