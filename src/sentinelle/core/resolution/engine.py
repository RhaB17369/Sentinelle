"""
Entity Resolution - ML-based Entity Clustering
Identifies when different identifiers belong to the same entity
"""

import logging
from typing import Dict, Any, List, Set, Tuple, Optional
from datetime import datetime
import hashlib
from collections import defaultdict


class EntityResolver:
    """
    Resolve entities using similarity metrics and clustering.
    
    Identifies when different domains, IPs, or identifiers belong to
    the same organization or threat actor.
    """
    
    def __init__(self, similarity_threshold: float = 0.7):
        """
        Initialize entity resolver.
        
        Args:
            similarity_threshold: Minimum similarity to consider same entity (0.0-1.0)
        """
        self.logger = logging.getLogger(__name__)
        self.threshold = similarity_threshold
        self.entity_clusters = {}
    
    def calculate_similarity(
        self,
        entity1: Dict[str, Any],
        entity2: Dict[str, Any]
    ) -> float:
        """
        Calculate similarity between two entities.
        
        Args:
            entity1: First entity data
            entity2: Second entity data
            
        Returns:
            Similarity score (0.0-1.0)
        """
        features = {}
        
        # WHOIS similarity
        if 'whois' in entity1 and 'whois' in entity2:
            features['whois'] = self._whois_similarity(
                entity1['whois'],
                entity2['whois']
            )
        
        # IP overlap
        if 'ips' in entity1 and 'ips' in entity2:
            features['ip_overlap'] = self._set_similarity(
                set(entity1['ips']),
                set(entity2['ips'])
            )
        
        # ASN match
        if 'asn' in entity1 and 'asn' in entity2:
            features['asn_match'] = 1.0 if entity1['asn'] == entity2['asn'] else 0.0
        
        # SSL CA match
        if 'ssl_ca' in entity1 and 'ssl_ca' in entity2:
            features['ssl_ca'] = 1.0 if entity1['ssl_ca'] == entity2['ssl_ca'] else 0.0
        
        # Nameserver overlap
        if 'nameservers' in entity1 and 'nameservers' in entity2:
            features['ns_overlap'] = self._set_similarity(
                set(entity1['nameservers']),
                set(entity2['nameservers'])
            )
        
        # Technology stack similarity
        if 'technologies' in entity1 and 'technologies' in entity2:
            features['tech_similarity'] = self._set_similarity(
                set(entity1['technologies']),
                set(entity2['technologies'])
            )
        
        # Temporal proximity (registration dates)
        if 'created_date' in entity1 and 'created_date' in entity2:
            features['temporal'] = self._temporal_similarity(
                entity1['created_date'],
                entity2['created_date']
            )
        
        # Weighted average
        if not features:
            return 0.0
        
        weights = {
            'whois': 0.25,
            'ip_overlap': 0.20,
            'asn_match': 0.15,
            'ssl_ca': 0.10,
            'ns_overlap': 0.15,
            'tech_similarity': 0.10,
            'temporal': 0.05,
        }
        
        total_weight = sum(weights.get(k, 0) for k in features.keys())
        if total_weight == 0:
            return 0.0
        
        similarity = sum(
            features[k] * weights.get(k, 0)
            for k in features.keys()
        ) / total_weight
        
        return similarity
    
    def _whois_similarity(self, whois1: Dict, whois2: Dict) -> float:
        """Calculate WHOIS similarity"""
        score = 0.0
        count = 0
        
        # Registrar match
        if whois1.get('registrar') and whois2.get('registrar'):
            count += 1
            if whois1['registrar'] == whois2['registrar']:
                score += 1.0
        
        # Organization match
        if whois1.get('org') and whois2.get('org'):
            count += 1
            if whois1['org'] == whois2['org']:
                score += 1.0
        
        # Email similarity
        if whois1.get('emails') and whois2.get('emails'):
            count += 1
            emails1 = set(whois1['emails']) if isinstance(whois1['emails'], list) else {whois1['emails']}
            emails2 = set(whois2['emails']) if isinstance(whois2['emails'], list) else {whois2['emails']}
            score += self._set_similarity(emails1, emails2)
        
        return score / count if count > 0 else 0.0
    
    def _set_similarity(self, set1: Set, set2: Set) -> float:
        """Calculate Jaccard similarity between sets"""
        if not set1 and not set2:
            return 0.0
        
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        
        return intersection / union if union > 0 else 0.0
    
    def _temporal_similarity(self, date1: str, date2: str) -> float:
        """Calculate temporal proximity"""
        try:
            from datetime import datetime
            
            # Parse dates (handle multiple formats)
            d1 = self._parse_date(date1)
            d2 = self._parse_date(date2)
            
            if not d1 or not d2:
                return 0.0
            
            # Calculate days difference
            diff_days = abs((d1 - d2).days)
            
            # Similarity decreases with time
            # Same day = 1.0, 30 days = 0.5, 365 days = 0.0
            if diff_days == 0:
                return 1.0
            elif diff_days <= 30:
                return 1.0 - (diff_days / 60)
            elif diff_days <= 365:
                return 0.5 - (diff_days - 30) / 730
            else:
                return 0.0
                
        except Exception as e:
            self.logger.debug(f"Temporal similarity error: {e}")
            return 0.0
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string"""
        if not date_str:
            return None
        
        # Try common formats
        formats = [
            '%Y-%m-%d',
            '%Y-%m-%d %H:%M:%S',
            '%d-%m-%Y',
            '%m/%d/%Y',
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(str(date_str)[:10], fmt[:10])
            except:
                continue
        
        return None
    
    def cluster_entities(
        self,
        entities: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """
        Cluster entities by similarity.
        
        Args:
            entities: List of entity data dictionaries
            
        Returns:
            Dictionary mapping cluster_id to list of entity identifiers
        """
        clusters = {}
        entity_to_cluster = {}
        next_cluster_id = 0
        
        for i, entity1 in enumerate(entities):
            entity1_id = entity1.get('id', f"entity_{i}")
            
            # Check if already clustered
            if entity1_id in entity_to_cluster:
                continue
            
            # Create new cluster
            cluster_id = f"cluster_{next_cluster_id}"
            clusters[cluster_id] = [entity1_id]
            entity_to_cluster[entity1_id] = cluster_id
            next_cluster_id += 1
            
            # Find similar entities
            for j, entity2 in enumerate(entities[i+1:], start=i+1):
                entity2_id = entity2.get('id', f"entity_{j}")
                
                # Skip if already clustered
                if entity2_id in entity_to_cluster:
                    continue
                
                # Calculate similarity
                similarity = self.calculate_similarity(entity1, entity2)
                
                if similarity >= self.threshold:
                    clusters[cluster_id].append(entity2_id)
                    entity_to_cluster[entity2_id] = cluster_id
                    
                    self.logger.info(
                        f"Clustered {entity1_id} and {entity2_id} "
                        f"(similarity: {similarity:.2f})"
                    )
        
        return clusters
    
    def resolve_entity(
        self,
        target_entity: Dict[str, Any],
        known_entities: List[Dict[str, Any]]
    ) -> List[Tuple[str, float]]:
        """
        Find entities similar to target.
        
        Args:
            target_entity: Entity to resolve
            known_entities: List of known entities
            
        Returns:
            List of (entity_id, similarity) tuples, sorted by similarity
        """
        matches = []
        
        for entity in known_entities:
            entity_id = entity.get('id', 'unknown')
            similarity = self.calculate_similarity(target_entity, entity)
            
            if similarity >= self.threshold:
                matches.append((entity_id, similarity))
        
        # Sort by similarity (descending)
        matches.sort(key=lambda x: x[1], reverse=True)
        
        return matches
    
    def generate_entity_fingerprint(self, entity: Dict[str, Any]) -> str:
        """
        Generate unique fingerprint for entity.
        
        Args:
            entity: Entity data
            
        Returns:
            Fingerprint hash
        """
        # Collect stable features
        features = []
        
        if 'whois' in entity:
            whois = entity['whois']
            if whois.get('org'):
                features.append(f"org:{whois['org']}")
            if whois.get('registrar'):
                features.append(f"registrar:{whois['registrar']}")
        
        if 'asn' in entity:
            features.append(f"asn:{entity['asn']}")
        
        if 'nameservers' in entity:
            ns_sorted = sorted(entity['nameservers'])
            features.append(f"ns:{','.join(ns_sorted)}")
        
        # Generate hash
        fingerprint_str = '|'.join(sorted(features))
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]
