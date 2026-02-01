#![deny(warnings)]

/// Web Scraping Engine for content extraction
#[derive(Debug)]
pub struct WebScrapingEngine;

impl WebScrapingEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WebScrapingEngine {
    fn default() -> Self {
        Self::new()
    }
}