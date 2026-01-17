
import asyncio
import logging
import json
from datetime import datetime
from typing import List, Dict, Any, Callable
from pathlib import Path

logger = logging.getLogger(__name__)

class MonitoringService:
    """
    Background daemon for continuous intelligence gathering.
    Monitors targets and alerts on changes in status, IP, or social presence.
    """
    
    def __init__(self, state_file: str = "monitoring_state.json"):
        self.targets = []
        self.state_file = Path(state_file)
        self.is_running = False
        self.interval = 3600  # Default 1 hour
        self.history = self._load_state()

    def _load_state(self) -> Dict:
        if self.state_file.exists():
            try:
                return json.loads(self.state_file.read_text())
            except:
                return {}
        return {}

    def _save_state(self):
        self.state_file.write_text(json.dumps(self.history, indent=4))

    def add_target(self, target_type: str, value: str):
        self.targets.append({'type': target_type, 'value': value})
        logger.info(f"Monitoring added: {target_type}:{value}")

    async def start(self, callback: Callable[[Dict], None]):
        """Start the monitoring loop."""
        self.is_running = True
        logger.info("Intelligence Monitoring Service Started")
        
        while self.is_running:
            for target in self.targets:
                await self._process_target(target, callback)
            
            await asyncio.sleep(self.interval)

    async def _process_target(self, target: Dict, callback: Callable):
        """Re-scan a target and compare with previous state."""
        # This would call the respective engine (Mail, Network, Social)
        # For now, we simulate a scan result
        now = datetime.now().isoformat()
        target_id = f"{target['type']}:{target['value']}"
        
        # Simulated scan
        current_data = {"last_seen": now, "status": "active"} 
        
        if target_id in self.history:
            old_data = self.history[target_id]
            if self._has_changed(old_data, current_data):
                callback({"event": "change_detected", "target": target, "data": current_data})
        
        self.history[target_id] = current_data
        self._save_state()

    def _has_changed(self, old: Dict, new: Dict) -> bool:
        # Deep compare logic here
        return old.get("status") != new.get("status")

    def stop(self):
        self.is_running = False
        logger.info("Intelligence Monitoring Service Stopped")
