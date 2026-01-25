use sentinelle_domain::{SigintTcpPort, TcpSigintResult, TcpSigintError};
use std::net::IpAddr;

pub struct RunSigintTcp<'a> {
    port: &'a dyn SigintTcpPort,
}

impl<'a> RunSigintTcp<'a> {
    pub fn new(port: &'a dyn SigintTcpPort) -> Self {
        Self { port }
    }

    pub fn execute(&self, target: IpAddr, port: u16) -> Result<TcpSigintResult, TcpSigintError> {
        self.port.probe(target, port)
    }
}