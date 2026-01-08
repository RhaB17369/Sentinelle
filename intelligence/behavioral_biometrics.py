"""
Behavioral Biometrics - User Identification by Behavior
Keystroke dynamics, mouse movement, writing style
"""

import logging
import numpy as np
from typing import Dict, List, Any


class BehavioralBiometrics:
    """Identify users by behavioral patterns"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.profiles = {}
    
    def create_typing_profile(self, keystroke_data: List[Dict]) -> np.ndarray:
        """Create typing profile from keystroke data"""
        features = []
        
        for i in range(len(keystroke_data) - 1):
            # Dwell time (how long key is pressed)
            dwell = keystroke_data[i].get('release_time', 0) - keystroke_data[i].get('press_time', 0)
            features.append(dwell)
            
            # Flight time (time between keys)
            flight = keystroke_data[i+1].get('press_time', 0) - keystroke_data[i].get('release_time', 0)
            features.append(flight)
        
        return np.array(features[:100])  # Limit to 100 features
    
    def match_profile(self, sample: np.ndarray, threshold: float = 0.85) -> Optional[str]:
        """Match sample against known profiles"""
        best_match = None
        best_score = 0.0
        
        for user_id, profile in self.profiles.items():
            # Cosine similarity
            if len(sample) == len(profile):
                similarity = np.dot(sample, profile) / (np.linalg.norm(sample) * np.linalg.norm(profile))
                
                if similarity > best_score:
                    best_score = similarity
                    best_match = user_id
        
        if best_score >= threshold:
            return best_match
        
        return None
