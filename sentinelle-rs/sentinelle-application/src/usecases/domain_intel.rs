use sentinelle_domain::{DomainIntelligencePort, DomainIntel, DomainIntelError};

pub struct RunDomainIntel<'a> {
    port: &'a dyn DomainIntelligencePort,
}

impl<'a> RunDomainIntel<'a> {
    pub fn new(port: &'a dyn DomainIntelligencePort) -> Self {
        Self { port }
    }

    pub fn execute(&self, domain: &str) -> Result<DomainIntel, DomainIntelError> {
        self.port.analyze(domain)
    }
}