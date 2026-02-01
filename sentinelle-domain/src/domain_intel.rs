#![deny(warnings)]

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct WhoisData {
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub name_servers: Vec<String>,
    pub org: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DnsRecords {
    pub a: Vec<String>,
    pub mx: Vec<String>,
    pub ns: Vec<String>,
    pub txt: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SslData {
    pub subject: HashMap<String, String>,
    pub issuer: HashMap<String, String>,
    pub not_after: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpData {
    pub status_code: u16,
    pub server: Option<String>,
    pub powered_by: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DomainIntel {
    pub domain: String,
    pub timestamp: String,
    pub whois: Option<WhoisData>,
    pub dns: Option<DnsRecords>,
    pub ssl: Option<SslData>,
    pub http: Option<HttpData>,
}

#[derive(Debug, thiserror::Error)]
pub enum DomainIntelError {
    #[error("invalid domain: {0}")]
    InvalidDomain(String),
    #[error("upstream failure")]
    UpstreamFailure,
}

/// Domain intelligence port (WHOIS, DNS, SSL, HTTP).
pub trait DomainIntelligencePort: Send + Sync {
    fn analyze(&self, domain: &str) -> Result<DomainIntel, DomainIntelError>;
}