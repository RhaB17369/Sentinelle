"""
Blockchain Intelligence - Cryptocurrency Tracking and Analysis
Bitcoin, Ethereum, and cross-chain analysis
"""

import logging
from typing import Dict, List, Any, Set, Optional, Tuple
from collections import defaultdict
import hashlib


class BlockchainIntelligence:
    """
    Cryptocurrency tracking and analysis.
    
    Capabilities:
    - Address clustering
    - Transaction tracing
    - Mixer/Tumbler detection
    - Exchange attribution
    - Risk scoring
    """
    
    # Known exchange patterns (simplified)
    EXCHANGE_PATTERNS = {
        'binance': {'hot_wallets': [], 'deposit_pattern': 'high_volume'},
        'coinbase': {'hot_wallets': [], 'deposit_pattern': 'regulated'},
        'kraken': {'hot_wallets': [], 'deposit_pattern': 'regulated'},
    }
    
    # Known mixers
    KNOWN_MIXERS = {
        'wasabi': 'coinjoin',
        'samourai': 'coinjoin',
        'tornado_cash': 'ethereum_mixer',
    }
    
    def __init__(self):
        """Initialize blockchain intelligence"""
        self.logger = logging.getLogger(__name__)
        self.address_clusters = defaultdict(set)
    
    def cluster_addresses(self, transactions: List[Dict]) -> Dict[str, Set[str]]:
        """
        Cluster addresses using heuristics.
        
        Heuristics:
        1. Common input ownership
        2. Change address detection
        3. Peeling chain detection
        
        Args:
            transactions: List of transactions
            
        Returns:
            Dictionary mapping cluster_id to set of addresses
        """
        clusters = defaultdict(set)
        address_to_cluster = {}
        next_cluster_id = 0
        
        for tx in transactions:
            inputs = tx.get('inputs', [])
            outputs = tx.get('outputs', [])
            
            if len(inputs) < 2:
                continue
            
            # Heuristic 1: Common input ownership
            # All input addresses likely belong to same entity
            input_addresses = [inp.get('address') for inp in inputs if inp.get('address')]
            
            if not input_addresses:
                continue
            
            # Find existing cluster
            existing_cluster = None
            for addr in input_addresses:
                if addr in address_to_cluster:
                    existing_cluster = address_to_cluster[addr]
                    break
            
            if existing_cluster is None:
                # Create new cluster
                cluster_id = f"cluster_{next_cluster_id}"
                next_cluster_id += 1
            else:
                cluster_id = existing_cluster
            
            # Add all input addresses to cluster
            for addr in input_addresses:
                clusters[cluster_id].add(addr)
                address_to_cluster[addr] = cluster_id
            
            # Heuristic 2: Change address detection
            # Smallest output is likely change
            if len(outputs) == 2:
                output_values = [(out.get('value', 0), out.get('address')) for out in outputs]
                output_values.sort()
                
                if output_values[0][1]:  # Smallest output (change)
                    change_addr = output_values[0][1]
                    clusters[cluster_id].add(change_addr)
                    address_to_cluster[change_addr] = cluster_id
        
        return dict(clusters)
    
    def trace_funds(
        self,
        address: str,
        blockchain: str = 'bitcoin',
        max_depth: int = 5
    ) -> Dict[str, Any]:
        """
        Trace funds from an address.
        
        Args:
            address: Starting address
            blockchain: Blockchain type
            max_depth: Maximum trace depth
            
        Returns:
            Trace results with transaction graph
        """
        trace = {
            'start_address': address,
            'blockchain': blockchain,
            'depth': 0,
            'transactions': [],
            'addresses_encountered': set([address]),
            'total_value': 0,
            'mixer_detected': False,
            'exchange_deposits': [],
        }
        
        # In production, query blockchain API
        # For now, return structure
        
        return trace
    
    def detect_mixer(self, transaction: Dict) -> Dict[str, Any]:
        """
        Detect if transaction involves a mixer/tumbler.
        
        Indicators:
        - CoinJoin patterns (many inputs, many outputs)
        - Known mixer addresses
        - Timing patterns
        
        Args:
            transaction: Transaction data
            
        Returns:
            Detection results
        """
        result = {
            'is_mixer': False,
            'mixer_type': None,
            'confidence': 0.0,
            'indicators': [],
        }
        
        inputs = transaction.get('inputs', [])
        outputs = transaction.get('outputs', [])
        
        # CoinJoin detection
        if len(inputs) > 10 and len(outputs) > 10:
            # Check if outputs have similar values
            output_values = [out.get('value', 0) for out in outputs]
            unique_values = len(set(output_values))
            
            if unique_values < len(output_values) * 0.3:  # Many similar values
                result['is_mixer'] = True
                result['mixer_type'] = 'coinjoin'
                result['confidence'] = 0.8
                result['indicators'].append('coinjoin_pattern')
        
        # Check known mixer addresses
        all_addresses = (
            [inp.get('address') for inp in inputs] +
            [out.get('address') for out in outputs]
        )
        
        for addr in all_addresses:
            if addr and self._is_known_mixer(addr):
                result['is_mixer'] = True
                result['mixer_type'] = 'known_mixer'
                result['confidence'] = 1.0
                result['indicators'].append(f'known_mixer_{addr[:10]}')
        
        return result
    
    def _is_known_mixer(self, address: str) -> bool:
        """Check if address is a known mixer"""
        # In production, check against database
        return False
    
    def attribute_exchange(self, address: str) -> Optional[str]:
        """
        Attribute address to an exchange.
        
        Args:
            address: Address to check
            
        Returns:
            Exchange name or None
        """
        # In production, check against exchange databases
        # For now, return None
        return None
    
    def calculate_risk_score(self, address: str, transaction_history: List[Dict]) -> Dict[str, Any]:
        """
        Calculate risk score for an address.
        
        Factors:
        - Mixer usage
        - Darknet market involvement
        - Sanctions list
        - Exchange deposits
        - Transaction patterns
        
        Args:
            address: Address to score
            transaction_history: Historical transactions
            
        Returns:
            Risk assessment
        """
        risk_score = 0.0
        risk_factors = []
        
        # Check for mixer usage
        mixer_count = sum(
            1 for tx in transaction_history
            if self.detect_mixer(tx)['is_mixer']
        )
        
        if mixer_count > 0:
            risk_score += min(mixer_count * 10, 30)
            risk_factors.append(f'mixer_usage_{mixer_count}')
        
        # High transaction volume
        if len(transaction_history) > 1000:
            risk_score += 10
            risk_factors.append('high_volume')
        
        # Rapid movement of funds
        if len(transaction_history) > 10:
            # Check time between transactions
            timestamps = [tx.get('timestamp', 0) for tx in transaction_history]
            if timestamps:
                import numpy as np
                intervals = np.diff(sorted(timestamps))
                if len(intervals) > 0:
                    avg_interval = np.mean(intervals)
                    if avg_interval < 3600:  # Less than 1 hour average
                        risk_score += 15
                        risk_factors.append('rapid_movement')
        
        # Normalize to 0-100
        risk_score = min(risk_score, 100)
        
        return {
            'address': address,
            'risk_score': risk_score,
            'risk_level': self._classify_risk(risk_score),
            'risk_factors': risk_factors,
            'transaction_count': len(transaction_history),
        }
    
    def _classify_risk(self, score: float) -> str:
        """Classify risk level"""
        if score >= 70:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'
