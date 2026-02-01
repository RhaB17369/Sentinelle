#![deny(warnings)]

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct TracerouteHopDetail {
    pub hop_index: u8,
    pub ip: String,
    pub rtt_ms: Option<f64>,
    pub asn: Option<String>,
    pub owner: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NetworkPathIntel {
    pub target: IpAddr,
    pub hops: Vec<TracerouteHopDetail>,
    pub as_path: Vec<String>,
    pub ixps: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum TracerouteSigintError {
    #[error("invalid target ip: {0}")]
    InvalidTarget(String),
    #[error("insufficient privileges for raw traceroute")]
    InsufficientPrivileges,
    #[error("probe failure")]
    ProbeFailure,
}

pub trait SigintTraceroutePort: Send + Sync {
    fn trace(&self, target: IpAddr, max_hops: u8) -> Result<NetworkPathIntel, TracerouteSigintError>;
}