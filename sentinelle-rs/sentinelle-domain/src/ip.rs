#![deny(warnings)]

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct IpIntelligence {
    pub ip: IpAddr,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
    pub isp: Option<String>,
    pub asn: Option<String>,
    pub ptr: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum IpIntelError {
    #[error("invalid ip address: {0}")]
    InvalidIp(String),
    #[error("provider failure")]
    ProviderFailure,
    #[error("no data available")]
    NoData,
}

pub trait IpIntelligencePort: Send + Sync {
    fn analyze_ip(&self, ip: IpAddr) -> Result<IpIntelligence, IpIntelError>;
}