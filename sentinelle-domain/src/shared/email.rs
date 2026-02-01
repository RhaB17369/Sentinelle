use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(String);

#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("invalid email format: {0}")]
    InvalidFormat(String),
}

static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
        .expect("valid email regex")
});

impl Email {
    pub fn parse(raw: &str) -> Result<Self, EmailError> {
        if EMAIL_RE.is_match(raw) {
            Ok(Self(raw.to_owned()))
        } else {
            Err(EmailError::InvalidFormat(raw.to_owned()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}