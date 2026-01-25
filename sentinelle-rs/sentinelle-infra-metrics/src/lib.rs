#![deny(warnings)]

use parking_lot::Mutex;
use sentinelle_domain::MetricsPort;
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Default)]
pub struct InMemoryMetrics {
    inner: Mutex&lt;Inner&gt;,
}

#[derive(Debug, Default)]
struct Inner {
    latencies: HashMap&lt;String, Vec&lt;Duration&gt;&gt;,
    successes: HashMap&lt;String, u64&gt;,
}

impl MetricsPort for InMemoryMetrics {
    fn observe_provider(&self, provider: &amp;str, latency: Duration, success: bool) {
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
    pub fn snapshot(&self) -&gt; (HashMap&lt;String, Vec&lt;Duration&gt;&gt;, HashMap&lt;String, u64&gt;) {
        let guard = self.inner.lock();
        (guard.latencies.clone(), guard.successes.clone())
    }
}