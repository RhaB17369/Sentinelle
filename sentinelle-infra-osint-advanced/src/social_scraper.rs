#![deny(warnings)]

/// Social Media Scraping Engine
#[derive(Debug)]
pub struct SocialScrapingEngine;

impl SocialScrapingEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SocialScrapingEngine {
    fn default() -> Self {
        Self::new()
    }
}