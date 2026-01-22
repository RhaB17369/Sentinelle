from dataclasses import dataclass
from typing import List, Optional
import importlib
import time
import inspect


@dataclass
class ModuleDefinition:
    id: str
    name: str
    status: str = "● PENDING"
    level: str = "OSINT"
    runner_method: str = ""
    version: Optional[str] = None
    load_time: Optional[float] = None
    progress: int = 0  # 0..100
    message: Optional[str] = None


class ModuleRegistry:
    """Dynamically discover available runner methods and probe their status.

    Discovery strategy:
    - Inspect `ModuleRunner` for methods named `run_*` and add them as modules
    - Use small, conservative imports and lightweight checks to verify operational status.
    - Record module import/load time and version when available.
    """

    # Map known runner methods to engine import paths and friendly names

    _KNOWN_MODULES = {
        'run_email_osint': (
            'email',
            'Email OSINT (Sentinelle)',
            'sentinelle.engines.mail.core',
        ),
        'run_phone_collector': (
            'phone',
            'Phone Intelligence',
            'sentinelle.engines.network.phone_locator',
        ),
        'run_ip_collector': (
            'ip',
            'IP Intelligence',
            'sentinelle.engines.network.geo',
        ),
        'run_social_engine': (
            'social',
            'Social Media Search (SocialEngine)',
            'sentinelle.engines.social.core',
        ),
        'run_domain_collector': (
            'domain',
            'Domain OSINT',
            'sentinelle.engines.network.domain_collector',
        ),
        'run_network_sigint': (
            'network_sigint',
            'Network SIGINT Analysis',
            'sentinelle.engines.network.latency_tracer',
        ),
    }

    def __init__(self):
        self.modules: List[ModuleDefinition] = []
        self.discover()

    def discover(self):
        """Discover runner methods and create ModuleDefinition placeholders."""
        self.modules = []
        try:
            from .runner import ModuleRunner
            methods = [
                m
                for m, _ in inspect.getmembers(
                    ModuleRunner, predicate=inspect.isfunction
                )
                if m.startswith('run_')
            ]
        except Exception:
            methods = []

        for method_name in methods:
            info = self._KNOWN_MODULES.get(method_name)
            if info:
                mod_id, friendly_name = info[0], info[1]
            else:
                # Fallback: derive id and name from method
                mod_id = method_name.replace('run_', '').split('_')[0]
                friendly_name = ' '.join(
                    part.capitalize() for part in method_name.replace('run_', '').split('_')
                )

            self.modules.append(
                ModuleDefinition(id=mod_id, name=friendly_name, runner_method=method_name)
            )

    def get_all(self) -> List[ModuleDefinition]:
        return self.modules

    def get_by_index(self, index: int) -> Optional[ModuleDefinition]:
        if 0 <= index < len(self.modules):
            return self.modules[index]
        return None

    def get_by_id(self, module_id: str) -> Optional[ModuleDefinition]:
        for mod in self.modules:
            if mod.id == module_id:
                return mod
        return None

    def probe_modules(self, timeout: float = 2.0):
        """Probe each known module by attempting a lightweight import and measuring load time.

        This method is intentionally conservative (only imports modules and reads their __version__ when available).
        It updates each ModuleDefinition in-place with status, version, load_time and progress.
        """
        for mod in self.modules:
            # Reset previous probe data
            mod.status = '● PENDING'
            mod.version = None
            mod.load_time = None
            mod.message = None
            mod.progress = 0

            # Determine import path based on known mapping
            method_name = mod.runner_method
            info = self._KNOWN_MODULES.get(method_name)
            if info:
                import_path = info[2]
            else:
                import_path = f'sentinelle.engines.{mod.id}'

            start = time.perf_counter()
            try:
                # attempt import with a short timeout by measuring elapsed time
                engine = importlib.import_module(import_path)
                elapsed = time.perf_counter() - start
                mod.load_time = round(elapsed, 2)
                # try to extract a __version__ attribute
                mod.version = getattr(engine, '__version__', None)
                mod.status = '✓ OPERATIONAL'
                mod.progress = 100
                mod.message = 'Ready'
            except ModuleNotFoundError as e:
                elapsed = time.perf_counter() - start
                mod.load_time = round(elapsed, 2)
                mod.status = '● MISSING'
                mod.progress = 0
                mod.message = str(e)
            except Exception as e:
                elapsed = time.perf_counter() - start
                mod.load_time = round(elapsed, 2)
                mod.status = '⚡ LOADING'
                # partial progress proportional to elapsed time (capped)
                mod.progress = min(int(min(elapsed / max(timeout, 0.001), 1.0) * 100), 99)
                mod.message = str(e)

        # Return updated module list for convenience
        return self.modules

    def _quick_probe(self, mod: ModuleDefinition, timeout: float = 2.0):
        """Perform a conservative, functional probe of the module.

        Strategy:
        - import module
        - if module exposes `health_check` callable, call it (must be quick)
        - else try to find a likely Engine/Collector class and instantiate without arguments
          (catch exceptions and mark as LOADING if it's safe to retry)
        - always respect the timeout and return a result dict
        """
        result = {'status': '● PENDING', 'progress': 0, 'message': None, 'version': None, 'load_time': None}
        method_name = mod.runner_method
        info = self._KNOWN_MODULES.get(method_name)
        if info:
            import_path = info[2]
        else:
            import_path = f'sentinelle.engines.{mod.id}'

        start = time.perf_counter()
        try:
            engine = importlib.import_module(import_path)
            elapsed = time.perf_counter() - start
            result['load_time'] = round(elapsed, 2)
            result['version'] = getattr(engine, '__version__', None)

            # Prefer explicit health_check hook if provided
            health = getattr(engine, 'health_check', None)
            if callable(health):
                try:
                    ok = health(timeout=timeout) if 'timeout' in inspect.signature(health).parameters else health()
                    if ok:
                        result.update({'status': '✓ OPERATIONAL', 'progress': 100, 'message': 'Ready'})
                    else:
                        result.update({'status': '⚠️ DEGRADED', 'progress': 50, 'message': 'Health check failed'})
                    return result
                except Exception as e:
                    # health_check failure marks as loading/degraded
                    result.update({'status': '⚡ LOADING', 'progress': 60, 'message': str(e)})
                    return result

            # Fallback: try to find a class named *Engine/*Collector/*Tracer and instantiate
            for name, obj in inspect.getmembers(engine, predicate=inspect.isclass):
                if any(s in name.lower() for s in ('engine', 'collector', 'tracer', 'core')):
                    try:
                        inst = obj()
                        # if instance has a lightweight 'probe' or 'check' method, call it
                        probe_fn = getattr(inst, 'probe', None) or getattr(inst, 'check', None)
                        if callable(probe_fn):
                            sig = inspect.signature(probe_fn)
                            if 'timeout' in sig.parameters:
                                ok = probe_fn(timeout=timeout)
                            else:
                                ok = probe_fn()

                            if ok:
                                result.update({'status': '✓ OPERATIONAL', 'progress': 100, 'message': 'Ready'})
                            else:
                                result.update({'status': '⚠️ DEGRADED', 'progress': 50, 'message': 'Probe failed'})
                            return result
                        # instantiation succeeded but no probe available -> consider operational
                        result.update({'status': '✓ OPERATIONAL', 'progress': 100, 'message': 'Instantiated'})
                        return result
                    except TypeError:
                        # cannot construct without args; skip to next
                        continue
                    except Exception as e:
                        result.update({'status': '⚡ LOADING', 'progress': 60, 'message': str(e)})
                        return result

            # If no explicit checks available, consider import success as operational
            result.update({'status': '✓ OPERATIONAL', 'progress': 100, 'message': 'Imported'})
            return result

        except ModuleNotFoundError as e:
            elapsed = time.perf_counter() - start
            result.update({'load_time': round(elapsed, 2), 'status': '● MISSING', 'progress': 0, 'message': str(e)})
            return result
        except Exception as e:
            elapsed = time.perf_counter() - start
            result.update({'load_time': round(elapsed, 2), 'status': '⚡ LOADING', 'progress': 30, 'message': str(e)})
            return result

    def probe_modules_deep(self, timeout: float = 2.0, concurrency: int = 4):
        """Perform deeper, concurrent probes of modules to verify functionality.

        This updates ModuleDefinition entries in-place during execution so a UI can
        poll or render updates in real-time.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Kick off the quick probes concurrently
        with ThreadPoolExecutor(max_workers=concurrency) as exe:
            futures = {exe.submit(self._quick_probe, mod, timeout): mod for mod in self.modules}
            for fut in as_completed(futures):
                mod = futures[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {'status': '⚡ LOADING', 'progress': 30, 'message': str(e)}

                # Apply results to the module object
                mod.status = res.get('status', mod.status)
                mod.progress = res.get('progress', mod.progress)
                mod.version = res.get('version', mod.version)
                mod.load_time = res.get('load_time', mod.load_time)
                mod.message = res.get('message', mod.message)

        return self.modules


# Create a module-level registry instance used by the UI
registry = ModuleRegistry()
