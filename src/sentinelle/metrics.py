"""Minimal optional metrics integration.
Tries to use prometheus_client if available; otherwise provides no-op functions.
"""
import time
import logging
import os
from typing import Dict

logger = logging.getLogger(__name__)

try:
    from prometheus_client import Counter, Histogram
    HAS_PROM = True
except Exception:
    HAS_PROM = False

SIMPLE_METRICS_ENABLED = os.getenv('SENTINELLE_SIMPLE_METRICS', '0') == '1'

# In-memory simple metrics store (used when SIMPLE_METRICS_ENABLED)
_SIMPLE_LATENCY: Dict[str, list] = {}
_SIMPLE_SUCCESS: Dict[str, int] = {}

if HAS_PROM:
    PROVIDER_LATENCY = Histogram('sentinelle_geo_provider_latency_seconds', 'Latency of geolocation providers', ['provider'])
    PROVIDER_SUCCESS = Counter('sentinelle_geo_provider_success_total', 'Successful geolocation provider calls', ['provider'])
elif SIMPLE_METRICS_ENABLED:
    class SimpleHistogram:
        def labels(self, **_k):
            return self

        def observe(self, value: float):
            # caller should pass provider in label; we keep simple store keyed later
            return None

    class SimpleCounter:
        def labels(self, **_k):
            return self

        def inc(self):
            return None

    PROVIDER_LATENCY = SimpleHistogram()
    PROVIDER_SUCCESS = SimpleCounter()
else:
    class _Noop:
        def __getattr__(self, name):
            def _(*_a, **_k):
                return None
            return _

    PROVIDER_LATENCY = _Noop()
    PROVIDER_SUCCESS = _Noop()


def observe_provider(provider: str, latency: float, success: bool):
    """Record provider latency/success into the configured backend.

    - Prometheus: uses the client library
    - Simple: stores metrics in in-memory dicts and logs them
    - No-op: does nothing
    """
    try:
        if HAS_PROM:
            PROVIDER_LATENCY.labels(provider=provider).observe(latency)
            if success:
                PROVIDER_SUCCESS.labels(provider=provider).inc()
            return

        if SIMPLE_METRICS_ENABLED:
            # Record in-memory
            _SIMPLE_LATENCY.setdefault(provider, []).append(latency)
            if success:
                _SIMPLE_SUCCESS[provider] = _SIMPLE_SUCCESS.get(provider, 0) + 1
            logger.debug("SimpleMetrics: provider=%s latency=%.3f success=%s", provider, latency, success)
            return

        # fallback: no-op implementation
        PROVIDER_LATENCY.labels(provider=provider).observe(latency)
        if success:
            PROVIDER_SUCCESS.labels(provider=provider).inc()
    except Exception:
        logger.debug("Metrics observe failed for provider %s", provider)


# Helper helpers usable in tests to inspect simple metrics
def _get_simple_metrics_snapshot():
    return {
        'latency': {k: list(v) for k, v in _SIMPLE_LATENCY.items()},
        'success': dict(_SIMPLE_SUCCESS),
    }
