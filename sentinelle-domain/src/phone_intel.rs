#![deny(warnings)]

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PhoneNumber(String);

#[derive(Debug, thiserror::Error)]
pub enum PhoneError {
    #[error("invalid phone format: {0}")]
    InvalidFormat(String),
}

impl PhoneNumber {
    pub fn new(raw: &str) -> Result<Self, PhoneError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(PhoneError::InvalidFormat(raw.to_string()));
        }
        // We leave strict validation to the infra layer (libphonenumber),
        // here we simply require the presence of at least one digit.
        if !trimmed.chars().any(|c| c.is_ascii_digit()) {
            return Err(PhoneError::InvalidFormat(raw.to_string()));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PhoneNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone)]
pub struct GpsLocation {
    pub lat: f64,
    pub lng: f64,
}

#[derive(Debug, Clone)]
pub struct PhoneIntel {
    pub phone_number: PhoneNumber,
    pub is_valid: bool,
    pub country: Option<String>,
    pub region: Option<String>,
    pub number_type: Option<String>,
    pub carrier: Option<String>,
    pub location: Option<String>,
    pub gps_coordinates: Option<GpsLocation>,
    pub geocoding_error: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PhoneIntelError {
    #[error("invalid phone: {0}")]
    InvalidPhone(String),
    #[error("upstream failure")]
    UpstreamFailure,
}

/// Phone intelligence port (equivalent PhoneTracer).
pub trait PhoneIntelligencePort: Send + Sync {
    fn analyze(&self, phone: PhoneNumber) -> Result<PhoneIntel, PhoneIntelError>;
}