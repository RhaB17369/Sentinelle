#![deny(warnings)]

use crate::shared::Email;

#[derive(Debug, Clone)]
pub struct MailServiceResult {
    pub service_name: String,
    pub exists: bool,
    pub rate_limited: bool,
    pub error: bool,
    pub email_recovery: Option<String>,
    pub phone_number: Option<String>,
    pub full_name: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MailScanSummary {
    pub email: Email,
    pub services: Vec<MailServiceResult>,
}

#[derive(Debug, thiserror::Error)]
pub enum MailScanError {
    #[error("invalid email: {0}")]
    InvalidEmail(String),
    #[error("scan failed")]
    ScanFailed,
}

pub trait MailIntelligencePort: Send + Sync {
    fn scan_email(&self, email: Email) -> Result<MailScanSummary, MailScanError>;
}