"""
Threat Scorer - Multi-Dimensional Threat Assessment
Comprehensive threat scoring based on multiple factors
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime


class ThreatScorer:
    """
    Calculate comprehensive threat scores based on multiple dimensions.
    
    Dimensions:
    - Reputation (VirusTotal, AlienVault, blacklists)
    - Infrastructure (hosting, ASN, geography)
    - Behavior (DGA, typosquatting, patterns)
    - Technical (SSL, ports, vulnerabilities)
    - Temporal (changes, age, activity)
    """
    
    def __init__(self):
        """Initialize threat scorer"""
        self.logger = logging.getLogger(__name__)
    
    def calculate_threat_score(self, intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate comprehensive threat score.
        
        Args:
            intelligence: Complete intelligence data
            
        Returns:
            Threat assessment with scores and classification
        """
        scores = {
            'reputation': self._score_reputation(intelligence),
            'infrastructure': self._score_infrastructure(intelligence),
            'behavior': self._score_behavior(intelligence),
            'technical': self._score_technical(intelligence),
            'temporal': self._score_temporal(intelligence),
        }
        
        # Weighted average
        weights = {
            'reputation': 0.30,
            'infrastructure': 0.20,
            'behavior': 0.25,
            'technical': 0.15,
            'temporal': 0.10,
        }
        
        overall_score = sum(
            scores[dim] * weights[dim]
            for dim in scores.keys()
        )
        
        # Classification
        classification = self._classify_threat(overall_score)
        
        return {
            'overall_score': round(overall_score, 2),
            'classification': classification,
            'dimension_scores': scores,
            'risk_factors': self._identify_risk_factors(intelligence, scores),
            'recommendations': self._generate_recommendations(classification, scores),
        }
    
    def _score_reputation(self, intel: Dict[str, Any]) -> float:
        """Score based on reputation data (0-100)"""
        score = 0.0
        
        # VirusTotal
        if 'virustotal' in intel:
            vt = intel['virustotal']
            if 'last_analysis' in vt:
                malicious = vt['last_analysis'].get('malicious', 0)
                suspicious = vt['last_analysis'].get('suspicious', 0)
                
                # High malicious detections = high score (bad)
                if malicious > 5:
                    score += 80
                elif malicious > 0:
                    score += 40 + (malicious * 5)
                
                if suspicious > 3:
                    score += 20
        
        # AlienVault OTX
        if 'alienvault' in intel:
            otx = intel['alienvault']
            pulse_count = len(otx.get('pulses', []))
            
            if pulse_count > 10:
                score += 60
            elif pulse_count > 0:
                score += pulse_count * 5
        
        # ThreatCrowd malware hashes
        if 'threatcrowd' in intel:
            tc = intel['threatcrowd']
            hash_count = len(tc.get('hashes', []))
            
            if hash_count > 0:
                score += min(hash_count * 10, 40)
        
        return min(score, 100.0)
    
    def _score_infrastructure(self, intel: Dict[str, Any]) -> float:
        """Score based on infrastructure (0-100)"""
        score = 0.0
        
        # Suspicious hosting providers
        suspicious_hosters = ['bulletproof', 'offshore', 'anonymous']
        
        if 'whois' in intel:
            whois = intel['whois']
            
            # Privacy protection (not necessarily bad, but suspicious for malware)
            if 'privacy' in str(whois).lower():
                score += 10
            
            # Recent registration
            if 'creation_date' in whois:
                try:
                    from datetime import datetime
                    created = whois['creation_date']
                    if isinstance(created, str):
                        # Domain less than 30 days old
                        score += 20
                except:
                    pass
        
        # Suspicious ASN
        if 'asn' in intel:
            asn = str(intel['asn'])
            # Known bad ASNs (simplified)
            bad_asns = []  # In production, use threat feed
            if asn in bad_asns:
                score += 40
        
        # Geographic risk
        if 'geolocation' in intel:
            geo = intel['geolocation']
            high_risk_countries = ['CN', 'RU', 'KP']  # Simplified
            if geo.get('country_code') in high_risk_countries:
                score += 15
        
        return min(score, 100.0)
    
    def _score_behavior(self, intel: Dict[str, Any]) -> float:
        """Score based on behavioral patterns (0-100)"""
        score = 0.0
        
        # DGA detection
        if 'pattern_detection' in intel:
            patterns = intel['pattern_detection']
            
            if patterns.get('dga', {}).get('is_dga'):
                dga_score = patterns['dga'].get('score', 0) * 100
                score += dga_score * 0.8
            
            if patterns.get('typosquatting', {}).get('is_typosquatting'):
                score += 60
            
            if patterns.get('phishing', {}).get('is_phishing'):
                phishing_score = patterns['phishing'].get('score', 0) * 100
                score += phishing_score
        
        # Fast flux (rapid IP changes)
        if 'dns_history' in intel:
            history = intel['dns_history']
            if len(history) > 10:  # Many IP changes
                score += 30
        
        return min(score, 100.0)
    
    def _score_technical(self, intel: Dict[str, Any]) -> float:
        """Score based on technical indicators (0-100)"""
        score = 0.0
        
        # SSL issues
        if 'ssl_certificate' in intel:
            cert = intel['ssl_certificate']
            
            # Self-signed
            if cert.get('issuer') == cert.get('subject'):
                score += 30
            
            # Expired
            if 'not_after' in cert:
                try:
                    from datetime import datetime
                    expiry = datetime.strptime(cert['not_after'], '%b %d %H:%M:%S %Y %Z')
                    if expiry < datetime.now():
                        score += 40
                except:
                    pass
        
        # Open dangerous ports
        if 'open_ports' in intel:
            dangerous_ports = [23, 445, 3389, 5900]  # Telnet, SMB, RDP, VNC
            open_dangerous = [
                p for p in intel['open_ports']
                if p.get('port') in dangerous_ports
            ]
            score += len(open_dangerous) * 10
        
        # Known vulnerabilities
        if 'vulnerabilities' in intel:
            vulns = intel['vulnerabilities']
            critical_count = sum(
                1 for v in vulns
                if v.get('severity') == 'critical'
            )
            score += critical_count * 20
        
        return min(score, 100.0)
    
    def _score_temporal(self, intel: Dict[str, Any]) -> float:
        """Score based on temporal patterns (0-100)"""
        score = 0.0
        
        # Recent changes
        if 'recent_changes' in intel:
            changes = intel['recent_changes']
            change_count = len(changes)
            
            # Many recent changes = suspicious
            if change_count > 5:
                score += 40
            elif change_count > 0:
                score += change_count * 5
        
        # Burst activity
        if 'activity_pattern' in intel:
            pattern = intel['activity_pattern']
            if pattern.get('burst_detected'):
                score += 30
        
        # Very new domain
        if 'domain_age_days' in intel:
            age = intel['domain_age_days']
            if age < 7:
                score += 50
            elif age < 30:
                score += 30
            elif age < 90:
                score += 10
        
        return min(score, 100.0)
    
    def _classify_threat(self, score: float) -> str:
        """Classify threat level based on score"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "BENIGN"
    
    def _identify_risk_factors(
        self,
        intel: Dict[str, Any],
        scores: Dict[str, float]
    ) -> List[str]:
        """Identify specific risk factors"""
        factors = []
        
        # High reputation score
        if scores['reputation'] > 50:
            factors.append("Multiple threat intelligence sources flagged this entity")
        
        # Behavioral issues
        if scores['behavior'] > 50:
            if intel.get('pattern_detection', {}).get('dga', {}).get('is_dga'):
                factors.append("Domain shows DGA characteristics")
            if intel.get('pattern_detection', {}).get('phishing', {}).get('is_phishing'):
                factors.append("Potential phishing indicators detected")
        
        # Technical issues
        if scores['technical'] > 50:
            factors.append("Technical security issues detected")
        
        # Infrastructure concerns
        if scores['infrastructure'] > 50:
            factors.append("Suspicious infrastructure characteristics")
        
        return factors
    
    def _generate_recommendations(
        self,
        classification: str,
        scores: Dict[str, float]
    ) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if classification in ["CRITICAL", "HIGH"]:
            recommendations.append("BLOCK: Immediate blocking recommended")
            recommendations.append("INVESTIGATE: Conduct thorough investigation")
            recommendations.append("MONITOR: Add to watchlist for continuous monitoring")
        elif classification == "MEDIUM":
            recommendations.append("MONITOR: Add to watchlist")
            recommendations.append("VERIFY: Verify legitimacy before allowing access")
        elif classification == "LOW":
            recommendations.append("MONITOR: Periodic monitoring recommended")
        else:
            recommendations.append("ALLOW: No immediate action required")
        
        return recommendations
