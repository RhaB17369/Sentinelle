#![deny(warnings)]

pub mod shared;
pub mod intel;
pub mod mail;
pub mod ip;
pub mod social;
pub mod metrics;
pub mod monitoring;
pub mod email_recon;
pub mod domain_intel;
pub mod latency_intel;
pub mod phone_intel;
pub mod sigint_tcp;
pub mod sigint_icmp;
pub mod sigint_traceroute;

pub use shared::{Email, EmailError};
pub use intel::{
    Entity, EntityId, EntityType, Confidence, ConfidenceError, AttributeValue,
    Relationship, RelationType, IntelligenceGraph, GraphError,
};
pub use mail::{MailIntelligencePort, MailScanSummary, MailScanError, MailServiceResult};
pub use ip::{IpIntelligencePort, IpIntelligence, IpIntelError};
pub use social::{
    SocialIntelligencePort, SocialScanResult, SocialScanError,
    SocialTarget, SocialAccount, AccountStatus,
};
pub use metrics::MetricsPort;
pub use monitoring::{Target, TargetType, TargetState, MonitoringEvent, detect_change};
pub use email_recon::{EmailReconPort, EmailReconResult, DnsProviderHint};
pub use domain_intel::{
    DomainIntelligencePort, DomainIntel, DomainIntelError,
    WhoisData, DnsRecords, SslData, HttpData,
};
pub use latency_intel::{
    LatencyIntelligencePort, LatencyIntel, LatencyIntelError,
    RttStats, LinkQuality, AsnInfo, TracerouteHop, TraceroutePath,
};
pub use phone_intel::{
    PhoneNumber, PhoneError, PhoneIntel, PhoneIntelError, PhoneIntelligencePort, GpsLocation,
};
pub use sigint_tcp::{SigintTcpPort, TcpSigintResult, TcpSigintError, TcpFingerprint};
pub use sigint_icmp::{SigintIcmpPort, IcmpSigintResult, IcmpSigintError, IpIdSeries, ClockSkew};
pub use sigint_traceroute::{
    SigintTraceroutePort, NetworkPathIntel, TracerouteSigintError, TracerouteHopDetail,
};