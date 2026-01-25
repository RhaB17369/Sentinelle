use std::collections::HashMap;
use std::time::SystemTime;

pub type EntityId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityType {
    Domain,
    Ip,
    Person,
    Location,
    Phone,
    Email,
    Organization,
    Certificate,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfidenceError {
    #[error("confidence must be in [0.0, 1.0], got {0}")]
    OutOfRange(f32),
}

#[derive(Debug, Clone, Copy)]
pub struct Confidence(f32);

impl Confidence {
    pub fn new(value: f32) -> Result<Self, ConfidenceError> {
        if (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ConfidenceError::OutOfRange(value))
        }
    }

    pub fn value(&self) -> f32 {
        self.0
    }

    pub fn max(self, other: Confidence) -> Confidence {
        if self.0 >= other.0 {
            self
        } else {
            other
        }
    }
}

#[derive(Debug, Clone)]
pub enum AttributeValue {
    Text(String),
    Number(f64),
    Boolean(bool),
    Timestamp(SystemTime),
}

#[derive(Debug, Clone)]
pub struct Entity {
    id: EntityId,
    kind: EntityType,
    attributes: HashMap<String, AttributeValue>,
    first_seen: SystemTime,
    last_seen: SystemTime,
    confidence: Confidence,
    sources: Vec<String>,
}

impl Entity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: EntityId,
        kind: EntityType,
        attributes: HashMap<String, AttributeValue>,
        first_seen: SystemTime,
        last_seen: SystemTime,
        confidence: Confidence,
        sources: Vec<String>,
    ) -> Self {
        Self {
            id,
            kind,
            attributes,
            first_seen,
            last_seen,
            confidence,
            sources,
        }
    }

    pub fn id(&self) -> &EntityId {
        &self.id
    }

    pub fn kind(&self) -> EntityType {
        self.kind
    }

    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    pub fn sources(&self) -> &[String] {
        &self.sources
    }

    pub fn attributes(&self) -> &HashMap<String, AttributeValue> {
        &self.attributes
    }

    pub fn first_seen(&self) -> SystemTime {
        self.first_seen
    }

    pub fn last_seen(&self) -> SystemTime {
        self.last_seen
    }

    pub fn with_updated(
        mut self,
        attributes: HashMap<String, AttributeValue>,
        last_seen: SystemTime,
        confidence: Confidence,
        extra_sources: Vec<String>,
    ) -> Self {
        for (k, v) in attributes {
            self.attributes.insert(k, v);
        }

        self.last_seen = last_seen;
        self.confidence = self.confidence.max(confidence);

        self.sources.extend(extra_sources);
        self.sources.sort();
        self.sources.dedup();

        self
    }
}