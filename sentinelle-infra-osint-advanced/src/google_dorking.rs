#![deny(warnings)]

/// Google Dorking Engine for advanced search queries
#[derive(Debug)]
pub struct GoogleDorkingEngine;

impl GoogleDorkingEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoogleDorkingEngine {
    fn default() -> Self {
        Self::new()
    }
}