from dataclasses importdataclass, field
from typing import List, Dict, Any
from datetime import datetime

@dataclass
class ActivityLog:
    timestamp: datetime
    message: str
    style: str = "white"

@dataclass
class AppState:
    """Singleton-like state container for the application"""
    active_modules_count: int = 11
    threats_detected: int = 0
    apt_attributions: int = 0
    blockchain_traces: int = 0
    
    activity_log: List[ActivityLog] = field(default_factory=list)
    
    def add_log(self, message: str, style: str = "green"):
        self.activity_log.append(ActivityLog(datetime.now(), message, style))
        # Keep only last 10 logs
        if len(self.activity_log) > 10:
            self.activity_log.pop(0)

# Global instance
state = AppState()
