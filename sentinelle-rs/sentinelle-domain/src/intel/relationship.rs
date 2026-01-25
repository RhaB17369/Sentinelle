use super::entity::{AttributeValue, Confidence, EntityId};
use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelationType {
    ResolvesTo,
    Hosts,
    Owns,
    LocatedAt,
    AssociatedWith,
    IssuedTo,
    Uses,
}

#[derive(Debug, Clone)]
pub struct Relationship {
    pub source: EntityId,
    pub target: EntityId,
    pub kind: RelationType,
    pub attributes: HashMap<String, AttributeValue>,
    pub timestamp: SystemTime,
    pub confidence: Confidence,
    pub sources: Vec<String>,
}