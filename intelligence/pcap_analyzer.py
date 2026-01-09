"""
PCAP Analyzer for Encrypted Traffic Analysis
Uses Scapy to parse PCAP files and extract TLS metadata for JA3/JA3S fingerprinting.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
import os

try:
    from scapy.all import rdpcap, PcapReader, TCP, IP, IPv6
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PcapAnalyzer:
    """
    Analyzes PCAP files to extract TLS session data.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy is not installed. Packet analysis will not work.")

    def process_pcap(self, pcap_path: str) -> List[Dict[str, Any]]:
        """
        Process a PCAP file and extract TLS sessions.

        Args:
            pcap_path: Path to .pcap or .pcapng file

        Returns:
            List of session dictionaries ready for analysis
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy required for PCAP analysis")

        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        sessions = []
        
        # Generator to handle large files efficiently
        try:
            packets = PcapReader(pcap_path)
        except Exception as e:
            self.logger.error(f"Failed to open PCAP: {e}")
            return []

        for pkt in packets:
            if not pkt.haslayer(TCP):
                continue
            
            # Check for TLS (Scapy's TLS detection isn't perfect, check payload)
            # Or trust scapy's layer decoding if available
            
            scapy_tls = False
            if pkt.haslayer(TLS):
               scapy_tls = True
            
            # Extract 5-tuple for session identification
            try:
                if pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                elif pkt.haslayer(IPv6):
                    src_ip = pkt[IPv6].src
                    dst_ip = pkt[IPv6].dst
                else:
                    continue
                
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                
                session_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                
                # Check for ClientHello
                if pkt.haslayer(TLSClientHello):
                    chello = pkt[TLSClientHello]
                    
                    # Extract JA3 components
                    client_hello_data = {
                        'version': chello.version,
                        'ciphers': chello.ciphers or [],
                        'extensions': [],
                        'curves': [],
                        'point_formats': []
                    }
                    
                    # Manual extension extraction/filtering might be needed depending on scapy version
                    # For now, we rely on Scapy's object structure
                    for ext in chello.extensions:
                        client_hello_data['extensions'].append(ext.type)
                        # EC Key Share / Supported Groups
                        if ext.type == 10: # supported_groups
                             client_hello_data['curves'] = ext.groups
                        # EC Point Formats
                        if ext.type == 11: # ec_point_formats
                             client_hello_data['point_formats'] = ext.ecpl
                    
                    sessions.append({
                        'session_id': session_id,
                        'src': src_ip,
                        'dst': dst_ip,
                        'client_hello': client_hello_data,
                        'timestamp': float(pkt.time)
                    })

                # Check for ServerHello
                elif pkt.haslayer(TLSServerHello):
                    shello = pkt[TLSServerHello]
                    
                    # Extract JA3S components
                    server_hello_data = {
                        'version': shello.version,
                        'cipher': shello.cipher,
                        'extensions': [ext.type for ext in shello.extensions]
                    }
                    
                    # Find matching session (naive mapping for this example)
                    # In a real stream reassembler, we'd match seq numbers
                    # Here we append as a new "session event" or try to merge
                    
                    sessions.append({
                        'session_id': session_id,
                        'src': src_ip,
                        'dst': dst_ip,
                        'server_hello': server_hello_data,
                        'timestamp': float(pkt.time)
                    })

            except Exception as e:
                # Malformed packet or parsing error
                continue
                
        return sessions
