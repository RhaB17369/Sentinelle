#![deny(warnings)]

/// Threat Intelligence Engine
#[derive(Debug)]
pub struct ThreatIntelEngine;

impl ThreatIntelEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ThreatIntelEngine {
    fn default() -> Self {
        Self::new()
    }
}