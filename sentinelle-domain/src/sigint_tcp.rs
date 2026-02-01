#![deny(warnings)]

use std::net::IpAddr;

use crate::ClockSkew;

#[derive(Debug, Clone)]
pub struct TcpFingerprint {
    pub window_size: u16,
    pub options: Vec<String>,
    pub wscale: Option<u8>,
    pub sack_permitted: bool,
    pub ts_val: Option<u32>,
    pub ts_ecr: Option<u32>,
    pub ttl: Option<u8>,
    pub ip_id: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct TcpSigintResult {
    pub target: IpAddr,
    pub port: u16,
    pub fingerprint: Option<TcpFingerprint>,
    pub clock_skew: Option<ClockSkew>,
    pub os_guess: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum TcpSigintError {
    #[error("invalid target ip: {0}")]
    InvalidTarget(String),
    #[error("insufficient privileges for raw tcp sigint")]
    InsufficientPrivileges,
    #[error("probe failure")]
    ProbeFailure,
}

/// SIGINT TCP port (fingerprint / OS / clock) at domain level.
pub trait SigintTcpPort: Send + Sync {
    fn probe(&self, target: IpAddr, port: u16) -> Result<TcpSigintResult, TcpSigintError>;
}