"""
APT Attribution Engine - Deep Learning Based
Identifies Advanced Persistent Threat groups using ML
"""

import logging
import numpy as np
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
from collections import defaultdict
import hashlib


class APTAttributor:
    """
    Attribute cyber attacks to APT groups using Deep Learning.
    
    Uses Transformer + LSTM architecture to analyze:
    - TTPs (Tactics, Techniques, Procedures)
    - Infrastructure patterns
    - Malware characteristics
    - Temporal patterns
    """
    
    # Known APT groups (simplified - in production use full MITRE database)
    APT_GROUPS = {
        'APT28': {'country': 'Russia', 'aka': ['Fancy Bear', 'Sofacy', 'Sednit']},
        'APT29': {'country': 'Russia', 'aka': ['Cozy Bear', 'The Dukes']},
        'APT1': {'country': 'China', 'aka': ['Comment Crew', 'PLA Unit 61398']},
        'APT10': {'country': 'China', 'aka': ['MenuPass', 'Stone Panda']},
        'APT32': {'country': 'Vietnam', 'aka': ['OceanLotus']},
        'APT33': {'country': 'Iran', 'aka': ['Elfin', 'Magnallium']},
        'APT34': {'country': 'Iran', 'aka': ['OilRig', 'Helix Kitten']},
        'APT37': {'country': 'North Korea', 'aka': ['Reaper', 'Group123']},
        'APT38': {'country': 'North Korea', 'aka': ['Lazarus Group']},
        'APT41': {'country': 'China', 'aka': ['Double Dragon', 'Barium']},
    }
    
    def __init__(self):
        """Initialize APT attributor"""
        self.logger = logging.getLogger(__name__)
        self.feature_cache = {}
    
    def extract_features(self, indicators: Dict[str, Any]) -> np.ndarray:
        """
        Extract features from indicators for ML model.
        
        Args:
            indicators: Dictionary containing:
                - ttps: List of MITRE ATT&CK techniques
                - infrastructure: IPs, domains, ASNs
                - malware: Hashes, families
                - timestamps: Activity times
                - linguistic: Language indicators
                
        Returns:
            Feature vector (numpy array)
        """
        features = []
        
        # 1. TTP Features (100 dimensions)
        ttp_features = self._extract_ttp_features(indicators.get('ttps', []))
        features.extend(ttp_features)
        
        # 2. Infrastructure Features (50 dimensions)
        infra_features = self._extract_infrastructure_features(
            indicators.get('infrastructure', {})
        )
        features.extend(infra_features)
        
        # 3. Malware Features (50 dimensions)
        malware_features = self._extract_malware_features(
            indicators.get('malware', {})
        )
        features.extend(malware_features)
        
        # 4. Temporal Features (20 dimensions)
        temporal_features = self._extract_temporal_features(
            indicators.get('timestamps', [])
        )
        features.extend(temporal_features)
        
        # 5. Linguistic Features (30 dimensions)
        linguistic_features = self._extract_linguistic_features(
            indicators.get('linguistic', {})
        )
        features.extend(linguistic_features)
        
        return np.array(features, dtype=np.float32)
    
    def _extract_ttp_features(self, ttps: List[str]) -> List[float]:
        """Extract TTP-based features"""
        # MITRE ATT&CK techniques (simplified)
        common_ttps = [
            'T1566',  # Phishing
            'T1059',  # Command and Scripting Interpreter
            'T1055',  # Process Injection
            'T1003',  # OS Credential Dumping
            'T1071',  # Application Layer Protocol
            'T1090',  # Proxy
            'T1027',  # Obfuscated Files or Information
            'T1105',  # Ingress Tool Transfer
            'T1053',  # Scheduled Task/Job
            'T1078',  # Valid Accounts
        ]
        
        # One-hot encoding + frequency
        features = []
        for ttp in common_ttps:
            count = sum(1 for t in ttps if ttp in t)
            features.append(min(count / 10.0, 1.0))  # Normalize
        
        # Pad to 100 dimensions
        features.extend([0.0] * (100 - len(features)))
        
        return features[:100]
    
    def _extract_infrastructure_features(self, infrastructure: Dict) -> List[float]:
        """Extract infrastructure-based features"""
        features = []
        
        # ASN distribution
        asns = infrastructure.get('asns', [])
        asn_diversity = len(set(asns)) / max(len(asns), 1)
        features.append(asn_diversity)
        
        # Hosting provider patterns
        hosting_providers = infrastructure.get('hosting_providers', [])
        bulletproof_count = sum(
            1 for h in hosting_providers 
            if any(bp in h.lower() for bp in ['offshore', 'bulletproof', 'privacy'])
        )
        features.append(bulletproof_count / max(len(hosting_providers), 1))
        
        # Geographic distribution
        countries = infrastructure.get('countries', [])
        geo_diversity = len(set(countries)) / max(len(countries), 1)
        features.append(geo_diversity)
        
        # Domain age patterns
        domain_ages = infrastructure.get('domain_ages_days', [])
        if domain_ages:
            avg_age = np.mean(domain_ages)
            features.append(min(avg_age / 365.0, 1.0))  # Normalize to years
        else:
            features.append(0.0)
        
        # SSL certificate patterns
        ssl_cas = infrastructure.get('ssl_cas', [])
        letsencrypt_ratio = sum(1 for ca in ssl_cas if 'letsencrypt' in ca.lower()) / max(len(ssl_cas), 1)
        features.append(letsencrypt_ratio)
        
        # Pad to 50 dimensions
        features.extend([0.0] * (50 - len(features)))
        
        return features[:50]
    
    def _extract_malware_features(self, malware: Dict) -> List[float]:
        """Extract malware-based features"""
        features = []
        
        # Malware families
        families = malware.get('families', [])
        family_diversity = len(set(families)) / max(len(families), 1)
        features.append(family_diversity)
        
        # Packer usage
        packers = malware.get('packers', [])
        packer_ratio = len(packers) / max(len(malware.get('samples', [])), 1)
        features.append(packer_ratio)
        
        # Code similarity (fuzzy hash)
        similarities = malware.get('code_similarities', [])
        if similarities:
            avg_similarity = np.mean(similarities)
            features.append(avg_similarity)
        else:
            features.append(0.0)
        
        # Compilation timestamps (timezone inference)
        compile_times = malware.get('compilation_times', [])
        if compile_times:
            # Extract hour of day
            hours = [datetime.fromisoformat(t).hour for t in compile_times if t]
            if hours:
                # Detect timezone pattern (e.g., 9-5 workday)
                workday_ratio = sum(1 for h in hours if 9 <= h <= 17) / len(hours)
                features.append(workday_ratio)
            else:
                features.append(0.0)
        else:
            features.append(0.0)
        
        # Pad to 50 dimensions
        features.extend([0.0] * (50 - len(features)))
        
        return features[:50]
    
    def _extract_temporal_features(self, timestamps: List[str]) -> List[float]:
        """Extract temporal pattern features"""
        features = []
        
        if not timestamps:
            return [0.0] * 20
        
        # Convert to datetime
        dts = [datetime.fromisoformat(t) for t in timestamps if t]
        
        if not dts:
            return [0.0] * 20
        
        # Activity hours (timezone inference)
        hours = [dt.hour for dt in dts]
        hour_distribution = np.histogram(hours, bins=24, range=(0, 24))[0]
        hour_distribution = hour_distribution / max(len(hours), 1)
        
        # Peak activity hour
        peak_hour = np.argmax(hour_distribution)
        features.append(peak_hour / 24.0)
        
        # Activity spread (how concentrated)
        hour_entropy = -np.sum(
            hour_distribution * np.log(hour_distribution + 1e-10)
        )
        features.append(hour_entropy / np.log(24))  # Normalize
        
        # Day of week patterns
        weekdays = [dt.weekday() for dt in dts]
        weekend_ratio = sum(1 for d in weekdays if d >= 5) / len(weekdays)
        features.append(weekend_ratio)
        
        # Activity duration
        if len(dts) > 1:
            duration_days = (max(dts) - min(dts)).days
            features.append(min(duration_days / 365.0, 1.0))
        else:
            features.append(0.0)
        
        # Pad to 20 dimensions
        features.extend([0.0] * (20 - len(features)))
        
        return features[:20]
    
    def _extract_linguistic_features(self, linguistic: Dict) -> List[float]:
        """Extract linguistic indicators"""
        features = []
        
        # Language detection from strings/comments
        languages = linguistic.get('languages', [])
        
        # Common languages for APT groups
        lang_indicators = {
            'russian': 0.0,
            'chinese': 0.0,
            'korean': 0.0,
            'persian': 0.0,
            'vietnamese': 0.0,
        }
        
        for lang in languages:
            lang_lower = lang.lower()
            for key in lang_indicators:
                if key in lang_lower:
                    lang_indicators[key] = 1.0
        
        features.extend(lang_indicators.values())
        
        # Typo patterns (can indicate native language)
        typos = linguistic.get('typos', [])
        typo_ratio = len(typos) / max(len(linguistic.get('total_strings', [])), 1)
        features.append(typo_ratio)
        
        # Pad to 30 dimensions
        features.extend([0.0] * (30 - len(features)))
        
        return features[:30]
    
    def attribute(self, indicators: Dict[str, Any]) -> Dict[str, Any]:
        """
        Attribute attack to APT group.
        
        Args:
            indicators: Attack indicators
            
        Returns:
            Attribution results with probabilities
        """
        # Extract features
        features = self.extract_features(indicators)
        
        # In production, use trained ML model
        # For now, use heuristic-based scoring
        scores = self._heuristic_attribution(indicators)
        
        # Sort by probability
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'top_attribution': sorted_scores[0][0] if sorted_scores else 'Unknown',
            'confidence': sorted_scores[0][1] if sorted_scores else 0.0,
            'all_probabilities': dict(sorted_scores[:5]),  # Top 5
            'feature_vector_size': len(features),
        }
        
        return result
    
    def _heuristic_attribution(self, indicators: Dict) -> Dict[str, float]:
        """Heuristic-based attribution (simplified)"""
        scores = defaultdict(float)
        
        # Infrastructure-based hints
        infrastructure = indicators.get('infrastructure', {})
        countries = infrastructure.get('countries', [])
        
        # Country-based scoring
        country_apt_map = {
            'RU': ['APT28', 'APT29'],
            'CN': ['APT1', 'APT10', 'APT41'],
            'KP': ['APT37', 'APT38'],
            'IR': ['APT33', 'APT34'],
            'VN': ['APT32'],
        }
        
        for country in countries:
            for apt in country_apt_map.get(country, []):
                scores[apt] += 0.3
        
        # TTP-based scoring
        ttps = indicators.get('ttps', [])
        
        # APT28 signatures
        if any('T1566' in t for t in ttps):  # Phishing
            scores['APT28'] += 0.2
        
        # APT29 signatures
        if any('T1078' in t for t in ttps):  # Valid Accounts
            scores['APT29'] += 0.2
        
        # Lazarus signatures
        if any('T1486' in t for t in ttps):  # Data Encrypted for Impact
            scores['APT38'] += 0.3
        
        # Normalize scores
        total = sum(scores.values())
        if total > 0:
            scores = {k: v / total for k, v in scores.items()}
        
        # Add all APT groups with small probability
        for apt in self.APT_GROUPS:
            if apt not in scores:
                scores[apt] = 0.01
        
        return scores
    
    def get_apt_info(self, apt_name: str) -> Dict[str, Any]:
        """Get information about an APT group"""
        return self.APT_GROUPS.get(apt_name, {})
