use sentinelle_domain::{IpIntelligencePort, IpIntelligence, IpIntelError};
use std::net::IpAddr;

pub struct RunIpIntelligence<'a> {
    ip_port: &'a dyn IpIntelligencePort,
}

impl<'a> RunIpIntelligence<'a> {
    pub fn new(ip_port: &'a dyn IpIntelligencePort) -> Self {
        Self { ip_port }
    }

    pub fn execute(&self, ip: IpAddr) -> Result<IpIntelligence, IpIntelError> {
        self.ip_port.analyze_ip(ip)
    }
}