"""
Confidence scoring system for intelligence assessments.
Provides Bayesian and statistical confidence estimation.
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import math


@dataclass
class ConfidenceScore:
    """Confidence score with justification"""
    score: float  # 0.0 to 1.0
    justification: str
    factors: Dict[str, float]  # Individual contributing factors
    
    def __post_init__(self):
        # Clamp score to [0, 1]
        self.score = max(0.0, min(1.0, self.score))


class ConfidenceScorer:
    """Calculate confidence scores for intelligence data"""
    
    # Source reliability weights (0.0 to 1.0)
    SOURCE_RELIABILITY = {
        'whois': 0.95,  # Official registrar data
        'dns': 0.95,    # DNS records are authoritative
        'ssl_cert': 0.90,  # Certificate data is cryptographically verified
        'geoip': 0.70,  # GeoIP is probabilistic
        'api': 0.85,    # Third-party APIs (varies by provider)
        'web_scrape': 0.60,  # Scraped data is less reliable
        'inference': 0.50,  # Inferred data
        'user_input': 0.30,  # User-provided data (unverified)
    }
    
    # Data freshness decay (half-life in days)
    FRESHNESS_HALF_LIFE = {
        'whois': 30,
        'dns': 7,
        'ssl_cert': 90,
        'geoip': 180,
        'api': 1,
        'web_scrape': 1,
        'inference': 7,
    }
    
    def __init__(self):
        pass
    
    def score_single_source(self, 
                           source_type: str, 
                           timestamp: Optional[datetime] = None) -> float:
        """
        Calculate confidence score for a single source.
        
        Args:
            source_type: Type of data source
            timestamp: When the data was collected (None = now)
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        # Base reliability
        base_score = self.SOURCE_RELIABILITY.get(source_type, 0.50)
        
        # Apply freshness decay
        if timestamp:
            age_days = (datetime.now() - timestamp).days
            half_life = self.FRESHNESS_HALF_LIFE.get(source_type, 7)
            
            # Exponential decay: score * (0.5 ^ (age / half_life))
            decay_factor = math.pow(0.5, age_days / half_life)
            score = base_score * decay_factor
        else:
            score = base_score
        
        return score
    
    def score_multi_source(self, 
                          sources: List[Tuple[str, Optional[datetime]]],
                          agreement: float = 1.0) -> ConfidenceScore:
        """
        Calculate confidence score from multiple sources.
        
        Args:
            sources: List of (source_type, timestamp) tuples
            agreement: Agreement level between sources (0.0 to 1.0)
                      1.0 = full agreement, 0.0 = complete disagreement
            
        Returns:
            ConfidenceScore object
        """
        if not sources:
            return ConfidenceScore(
                score=0.0,
                justification="No sources available",
                factors={}
            )
        
        # Calculate individual source scores
        source_scores = {}
        for source_type, timestamp in sources:
            score = self.score_single_source(source_type, timestamp)
            source_scores[source_type] = score
        
        # Combine scores using Bayesian approach
        # P(true | sources) ∝ product of individual probabilities
        combined_score = self._bayesian_combine(list(source_scores.values()))
        
        # Apply agreement factor
        final_score = combined_score * agreement
        
        # Generate justification
        justification = self._generate_justification(
            source_scores, agreement, final_score
        )
        
        return ConfidenceScore(
            score=final_score,
            justification=justification,
            factors=source_scores
        )
    
    def _bayesian_combine(self, scores: List[float]) -> float:
        """
        Combine multiple probability scores using Bayesian approach.
        
        Assumes independence of sources.
        """
        if not scores:
            return 0.0
        
        # Convert scores to odds
        odds = []
        for score in scores:
            if score == 0:
                odds.append(0)
            elif score == 1:
                odds.append(float('inf'))
            else:
                odds.append(score / (1 - score))
        
        # Multiply odds
        combined_odds = 1.0
        for odd in odds:
            if odd == float('inf'):
                return 1.0
            combined_odds *= odd
        
        # Convert back to probability
        if combined_odds == 0:
            return 0.0
        
        combined_prob = combined_odds / (1 + combined_odds)
        
        # Normalize to prevent overconfidence
        # Use geometric mean instead of product for multiple sources
        n = len(scores)
        if n > 1:
            geometric_mean = math.pow(combined_prob, 1.0 / n)
            # Blend between geometric mean and combined probability
            combined_prob = 0.7 * combined_prob + 0.3 * geometric_mean
        
        return combined_prob
    
    def _generate_justification(self, 
                                source_scores: Dict[str, float],
                                agreement: float,
                                final_score: float) -> str:
        """Generate human-readable justification for confidence score"""
        parts = []
        
        # Describe confidence level
        if final_score >= 0.9:
            parts.append("Very high confidence")
        elif final_score >= 0.75:
            parts.append("High confidence")
        elif final_score >= 0.6:
            parts.append("Moderate confidence")
        elif final_score >= 0.4:
            parts.append("Low confidence")
        else:
            parts.append("Very low confidence")
        
        # Describe sources
        num_sources = len(source_scores)
        if num_sources == 1:
            source_name = list(source_scores.keys())[0]
            parts.append(f"based on single source ({source_name})")
        else:
            parts.append(f"based on {num_sources} sources")
        
        # Describe agreement
        if num_sources > 1:
            if agreement >= 0.9:
                parts.append("with strong agreement")
            elif agreement >= 0.7:
                parts.append("with moderate agreement")
            else:
                parts.append("with weak agreement")
        
        # List top sources
        if num_sources > 1:
            top_sources = sorted(source_scores.items(), 
                               key=lambda x: x[1], 
                               reverse=True)[:3]
            source_list = ", ".join([s[0] for s in top_sources])
            parts.append(f"(primary sources: {source_list})")
        
        return " ".join(parts) + "."
    
    def score_cross_validation(self, 
                              data_points: List[any],
                              expected_value: any) -> float:
        """
        Score confidence based on cross-validation.
        
        Args:
            data_points: List of data points from different sources
            expected_value: Expected/consensus value
            
        Returns:
            Confidence score based on agreement
        """
        if not data_points:
            return 0.0
        
        # Count matches
        matches = sum(1 for dp in data_points if dp == expected_value)
        
        # Calculate agreement ratio
        agreement = matches / len(data_points)
        
        return agreement
    
    def quantify_uncertainty(self, 
                            data_points: List[float]) -> Tuple[float, float]:
        """
        Quantify uncertainty in numerical data.
        
        Args:
            data_points: List of numerical values
            
        Returns:
            Tuple of (mean, standard_deviation)
        """
        if not data_points:
            return 0.0, 0.0
        
        n = len(data_points)
        mean = sum(data_points) / n
        
        if n == 1:
            return mean, 0.0
        
        variance = sum((x - mean) ** 2 for x in data_points) / (n - 1)
        std_dev = math.sqrt(variance)
        
        return mean, std_dev
