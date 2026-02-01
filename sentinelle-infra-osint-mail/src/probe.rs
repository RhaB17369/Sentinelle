use async_trait::async_trait;
use md5;
use reqwest::Client;
use sentinelle_domain::{Email, MailServiceResult};

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("http error")]
    Http,
    #[error("unexpected response")]
    UnexpectedResponse,
}

/// Abstraction d'un "site" ou service testant l'existence d'un email.
#[async_trait]
pub trait MailServiceProbe: Send + Sync {
    fn name(&self) -> &'static str;

    async fn probe(
        &self,
        client: &Client,
        email: &Email,
    ) -> Result<MailServiceResult, ProbeError>;
}

/// Probe réelle : vérifie la présence d'un avatar Gravatar pour l'email.
/// Gravatar est massivement utilisé et fournit un signal OSINT fiable
/// sur l'existence d'un compte lié à cet email.
#[derive(Debug, Default)]
pub struct GravatarProbe;

#[async_trait]
impl MailServiceProbe for GravatarProbe {
    fn name(&self) -> &'static str {
        "gravatar"
    }

    async fn probe(
        &self,
        client: &Client,
        email: &Email,
    ) -> Result<MailServiceResult, ProbeError> {
        // Gravatar utilise MD5 de l'email normalisé (trim + lowercase)
        let normalized = email.as_str().trim().to_lowercase();
        let hash = format!("{:x}", md5::compute(normalized.as_bytes()));
        let url = format!("https://www.gravatar.com/avatar/{hash}?d=404");

        let resp = client
            .head(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| {
                eprintln!("Gravatar request failed: {}", e);
                ProbeError::Http
            })?;
        let status = resp.status();

        let (exists, error) = if status.is_success() {
            (true, false)
        } else if status.as_u16() == 404 {
            (false, false)
        } else {
            eprintln!("Gravatar returned unexpected status: {}", status);
            (false, true)
        };

        Ok(MailServiceResult {
            service_name: self.name().to_string(),
            exists,
            rate_limited: false,
            error,
            email_recovery: None,
            phone_number: None,
            full_name: None,
            created_at: None,
        })
    }
}