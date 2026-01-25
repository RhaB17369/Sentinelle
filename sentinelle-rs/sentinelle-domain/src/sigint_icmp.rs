#![deny(warnings)]

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct IpIdSeries {
    pub ids: Vec<u16>,
    pub classification: String, // constant / incremental / random / mixed / error
}

#[derive(Debug, Clone)]
pub struct ClockSkew {
    pub hz: f64,
    pub sample_count: usize,
}

#[derive(Debug, Clone)]
pub struct IcmpSigintResult {
    pub target: IpAddr,
    pub ip_id_series: Option<IpIdSeries>,
    pub clock_skew: Option<ClockSkew>,
}

#[derive(Debug, thiserror::Error)]
pub enum IcmpSigintError {
    #[error("invalid target ip: {0}")]
    InvalidTarget(String),
    #[error("insufficient privileges for raw icmp sigint")]
    InsufficientPrivileges,
    #[error("probe failure")]
    ProbeFailure,
}

pub trait SigintIcmpPort: Send + Sync {
    fn probe(&self, target: IpAddr) -> Result<IcmpSigintResult, IcmpSigintError>;
}