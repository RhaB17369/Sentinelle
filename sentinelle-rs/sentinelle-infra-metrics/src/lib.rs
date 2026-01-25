#![deny(warnings)]

use parking_lot::Mutex;
use sentinelle_domain::MetricsPort;
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Default)]
pub struct InMemoryMetrics {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    latencies: HashMap<String, Vec<Duration>>,
    successes: HashMap<String, u64>,
}

impl MetricsPort for InMemoryMetrics {
    fn observe_provider(&self, provider: &str, latency: Duration, success: bool) {
        let mut guard = self.inner.lock();
        guard
            .latencies
            .entry(provider.to_string())
            .or_default()
            .push(latency);
        if success {
            *guard.successes.entry(provider.to_string()).or_insert(0) += 1;
        }
    }
}

impl InMemoryMetrics {
    pub fn snapshot(&self) -> (HashMap<String, Vec<Duration>>, HashMap<String, u64>) {
        let guard = self.inner.lock();
        (guard.latencies.clone(), guard.successes.clone())
    }
}