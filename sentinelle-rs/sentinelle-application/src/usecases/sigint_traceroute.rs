use sentinelle_domain::{SigintTraceroutePort, NetworkPathIntel, TracerouteSigintError};
use std::net::IpAddr;

pub struct RunSigintTraceroute<'a> {
    port: &'a dyn SigintTraceroutePort,
}

impl<'a> RunSigintTraceroute<'a> {
    pub fn new(port: &'a dyn SigintTraceroutePort) -> Self {
        Self { port }
    }

    pub fn execute(&self, target: IpAddr, max_hops: u8) -> Result<NetworkPathIntel, TracerouteSigintError> {
        self.port.trace(target, max_hops)
    }
}