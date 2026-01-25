use sentinelle_domain::{LatencyIntelligencePort, LatencyIntel, LatencyIntelError};
use std::net::IpAddr;

pub struct RunLatencyIntel<'a> {
    port: &'a dyn LatencyIntelligencePort,
}

impl<'a> RunLatencyIntel<'a> {
    pub fn new(port: &'a dyn LatencyIntelligencePort) -> Self {
        Self { port }
    }

    pub fn execute(&self, target: IpAddr) -> Result<LatencyIntel, LatencyIntelError> {
        self.port.analyze(target)
    }
}