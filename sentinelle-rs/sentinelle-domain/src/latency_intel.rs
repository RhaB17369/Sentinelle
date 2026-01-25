#![deny(warnings)]

use std::net::IpAddr;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct RttStats {
    pub min: f64,
    pub avg: f64,
    pub max: f64,
    pub mdev: f64,
    pub loss_pct: f64,
}

#[derive(Debug, Clone)]
pub struct LinkQuality {
    pub quality_score: f64,
    pub rating: String,
    pub packet_loss_pct: f64,
}

#[derive(Debug, Clone)]
pub struct AsnInfo {
    pub asn: Option<String>,
    pub prefix: Option<String>,
    pub country: Option<String>,
    pub owner: Option<String>,
    pub is_known_vpn: bool,
}

#[derive(Debug, Clone)]
pub struct TracerouteHop {
    pub ip: String,
    pub asn: Option<String>,
    pub owner: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TraceroutePath {
    pub hop_count: usize,
    pub hops: Vec<TracerouteHop>,
    pub ixps: Vec<String>,
    pub as_path: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LatencyIntel {
    pub target: IpAddr,
    pub rtt: Option<RttStats>,
    pub jitter_ms: Option<f64>,
    pub link_medium: Option<String>,
    pub link_quality: Option<LinkQuality>,
    pub asn: Option<AsnInfo>,
    pub traceroute: Option<TraceroutePath>,
    pub distance_km: Option<f64>,
    pub distance_margin_km: Option<f64>,
    pub extra: HashMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum LatencyIntelError {
    #[error("invalid ip: {0}")]
    InvalidIp(String),
    #[error("upstream failure")]
    UpstreamFailure,
}

/// Port de renseignement de latence / chemin réseau.
/// Remplace LatencyTracer côté Rust.
pub trait LatencyIntelligencePort: Send + Sync {
    fn analyze(&self, target: IpAddr) -> Result<LatencyIntel, LatencyIntelError>;
}