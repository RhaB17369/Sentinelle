#![deny(warnings)]

use std::time::Duration;

pub trait MetricsPort: Send + Sync {
    fn observe_provider(&self, provider: &str, latency: Duration, success: bool);
}