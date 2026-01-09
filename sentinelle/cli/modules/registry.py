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
            ModuleDefinition("apt", "APT Attribution", "✓ Ready", "NSA", "run_apt_attribution"),
            ModuleDefinition("traffic", "Traffic Analysis", "✓ Ready", "NSA", "run_traffic_analysis"),
            ModuleDefinition("blockchain", "Blockchain Intel", "✓ Ready", "CIA", "run_blockchain_intel"),
            ModuleDefinition("steg", "Steganalysis", "✓ Ready", "8200", "run_steganalysis"),
            ModuleDefinition("sigint", "Passive SIGINT", "✓ Ready", "GCHQ", "run_passive_sigint"),
            ModuleDefinition("deanon", "De-anonymization", "✓ Ready", "NSA", "run_deanonymization"),
            ModuleDefinition("bio", "Behavioral Bio", "✓ Ready", "CIA", "run_behavioral_biometrics"),
            ModuleDefinition("hunter", "AI Threat Hunter", "✓ Ready", "8200", "run_ai_threat_hunter"),
            ModuleDefinition("predictor", "Attack Predictor", "✓ Ready", "NSA", "run_attack_predictor"),
            ModuleDefinition("persona", "Persona Profiler", "✓ Ready", "CIA", "run_persona_profiler"),
            ModuleDefinition("malware", "Malware Genome", "⏳ Dev", "8200", "run_malware_genome"),
        ]

    def get_all(self) -> List[ModuleDefinition]:
        return self.modules

    def get_by_index(self, index: int) -> Optional[ModuleDefinition]:
        # adjusting for 1-based index from menu
        if 0 <= index < len(self.modules):
            return self.modules[index]
        return None

registry = ModuleRegistry()
