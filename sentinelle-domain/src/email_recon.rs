#![deny(warnings)]

use crate::Email;
use std::net::IpAddr;

/// Hints on providers and mail infrastructure derived from DNS/SPF/DMARC/MX.
#[derive(Debug, Clone)]
pub struct DnsProviderHint {
    pub domain: String,
    pub mx_hosts: Vec<String>,
    pub spf_record: Option<String>,
    pub dmarc_record: Option<String>,
    pub dkim_selectors: Vec<String>,
    pub inferred_providers: Vec<String>,
}

/// Global email passive reconnaissance result (government level).
#[derive(Debug, Clone)]
pub struct EmailReconResult {
    pub email: Email,
    pub domain: String,
    pub dns: Option<DnsProviderHint>,
    pub ct_domains: Vec<String>,
    pub archive_hits: u64,
    pub common_crawl_hits: u64,
    pub related_ips: Vec<IpAddr>,
}

#[derive(Debug, thiserror::Error)]
pub enum EmailReconError {
    #[error("invalid email: {0}")]
    InvalidEmail(String),
    #[error("upstream failure")]
    UpstreamFailure,
}

/// Passive email reconnaissance port.
/// Implemented on infra side via CT logs, DNS, archives, public indexes, etc.
pub trait EmailReconPort: Send + Sync {
    fn recon(&self, email: Email) -> Result<EmailReconResult, EmailReconError>;
}