use sentinelle_domain::{MailIntelligencePort, MailScanSummary, MailScanError, Email};

pub struct RunMailScan<'a> {
    mail_port: &'a dyn MailIntelligencePort,
}

impl<'a> RunMailScan<'a> {
    pub fn new(mail_port: &'a dyn MailIntelligencePort) -> Self {
        Self { mail_port }
    }

    pub fn execute(&self, email: Email) -> Result<MailScanSummary, MailScanError> {
        self.mail_port.scan_email(email)
    }
}