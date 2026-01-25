use sentinelle_domain::{SigintIcmpPort, IcmpSigintResult, IcmpSigintError};
use std::net::IpAddr;

pub struct RunSigintIcmp<'a> {
    port: &'a dyn SigintIcmpPort,
}

impl<'a> RunSigintIcmp<'a> {
    pub fn new(port: &'a dyn SigintIcmpPort) -> Self {
        Self { port }
    }

    pub fn execute(&self, target: IpAddr) -> Result<IcmpSigintResult, IcmpSigintError> {
        self.port.probe(target)
    }
}