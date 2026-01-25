#![deny(warnings)]

pub mod shared;
pub mod intel;
pub mod mail;
pub mod ip;
pub mod social;
pub mod metrics;
pub mod monitoring;

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