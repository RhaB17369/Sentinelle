#![deny(warnings)]

use crate::shared::Email;

#[derive(Debug, Clone)]
pub enum SocialTarget {
    Username(String),
    Email(Email),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    Found,
    NotFound,
    Error,
}

#[derive(Debug, Clone)]
pub struct SocialAccount {
    pub site_name: String,
    pub profile_url: Option<String>,
    pub status: AccountStatus,
}

#[derive(Debug, Clone)]
pub struct SocialScanResult {
    pub target: SocialTarget,
    pub accounts: Vec<SocialAccount>,
    pub ai_analysis: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum SocialScanDepth {
    Fast,
    Standard,
    Deep,
}

#[derive(Debug, Clone)]
pub struct SocialScanOptions {
    pub depth: SocialScanDepth,
}

impl Default for SocialScanOptions {
    fn default() -> Self {
        Self {
            depth: SocialScanDepth::Standard,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SocialScanError {
    #[error("invalid input")]
    Input,
    #[error("external failure")]
    External,
}

pub trait SocialIntelligencePort: Send + Sync {
    fn scan(&self, target: SocialTarget) -> Result<SocialScanResult, SocialScanError>;

    fn scan_with_options(
        &self,
        target: SocialTarget,
        options: SocialScanOptions,
    ) -> Result<SocialScanResult, SocialScanError> {
        let _ = options;
        self.scan(target)
    }
}