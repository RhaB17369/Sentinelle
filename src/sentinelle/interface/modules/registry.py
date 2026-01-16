from dataclasses import dataclass
from typing import List, Callable, Optional

@dataclass
class ModuleDefinition:
    id: str
    name: str
    status: str
    level: str
    runner_method: str  # Name of the method in the runner to execute

class ModuleRegistry:
    def __init__(self):
        self.modules: List[ModuleDefinition] = [
            ModuleDefinition("email", "Email OSINT (Sentinelle)", "✓ Operational", "OSINT", "run_email_osint"),
            ModuleDefinition("phone", "Phone Intelligence", "✓ Operational", "OSINT", "run_phone_collector"),
            ModuleDefinition("ip", "IP Intelligence", "✓ Operational", "OSINT", "run_ip_collector"),
            ModuleDefinition("social", "Social Media Search (SocialEngine)", "✓ Operational", "OSINT", "run_social_engine"),
        ]

    def get_all(self) -> List[ModuleDefinition]:
        return self.modules

    def get_by_index(self, index: int) -> Optional[ModuleDefinition]:
        # adjusting for 1-based index from menu
        if 0 <= index < len(self.modules):
            return self.modules[index]
        return None

    def get_by_id(self, module_id: str) -> Optional[ModuleDefinition]:
        for mod in self.modules:
            if mod.id == module_id:
                return mod
        return None

registry = ModuleRegistry()
