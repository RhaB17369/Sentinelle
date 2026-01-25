use sentinelle_domain::{EmailReconPort, EmailReconResult, EmailReconError, Email};

pub struct RunEmailRecon<'a> {
    port: &'a dyn EmailReconPort,
}

impl<'a> RunEmailRecon<'a> {
    pub fn new(port: &'a dyn EmailReconPort) -> Self {
        Self { port }
    }

    pub fn execute(&self, email: Email) -> Result<EmailReconResult, EmailReconError> {
        self.port.recon(email)
    }
}